/*
 * Memory region management for Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/madvise.h"
#include "qemu/mprotect.h"
#include "qemu/memalign.h"
#include "qemu/cacheinfo.h"
#include "qemu/qtree.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "tcg/tcg.h"
#include "exec/translation-block.h"
#include "tcg-internal.h"
#include "tcg/hybrid.h"
#include "host/cpuinfo.h"


/*
 * Local source-level compatibility with Unix.
 * Used by tcg_region_init below.
 */
#if defined(_WIN32)
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4
#endif

struct tcg_region_tree {
    QemuMutex lock;
    QTree *tree;
    /* padding to avoid false sharing is computed at run-time */
};

/*
 * We divide code_gen_buffer into equally-sized "regions" that TCG threads
 * dynamically allocate from as demand dictates. Given appropriate region
 * sizing, this minimizes flushes even when some TCG threads generate a lot
 * more code than others.
 */
struct tcg_region_state {
    QemuMutex lock;

    /* fields set at init time */
    void *start_aligned;
    void *after_prologue;
    size_t n;
    size_t size; /* size of one region */
    size_t stride; /* .size + guard size */
    size_t total_size; /* size of entire buffer, >= n * stride */
    size_t min_available; /* regions the vCPUs must be able to hold at once */
    bool ready; /* set last, once every field above is safe to read */

    /* fields protected by the lock */
    size_t current; /* current region index */
    size_t available; /* regions that may be handed out; <= .n */
    size_t agg_size_full; /* aggregate size of full regions */
};

static struct tcg_region_state region;

/*
 * How much of the code buffer has been prepared for execution, in bytes.
 *
 * Measured from region.start_aligned, which -- unlike QEMU 6's
 * code_gen_buffer -- never moves: the prologue is carved off via
 * region.after_prologue rather than by advancing the base, so the boundary
 * blessed at allocation time is still the boundary everything else reads.
 */
static size_t tctish_usable_bytes;

/*
 * Whether the buffer was actually brought into use a chunk at a time.
 *
 * Distinct from `tctish_usable_bytes == total`, which is also what an ordinary
 * unchunked start looks like once it has been filled in. Only this says whether
 * the region layout has to be fine enough to subdivide, and a host that never
 * chunked must keep the partitioning it has always had.
 */
static bool tctish_chunked;

/*
 * Serialises growing, shrinking, and handing memory back.
 *
 * These run on three different threads -- the app's own for grow and shrink,
 * whichever vCPU reached the flush for the release -- and the release reads the
 * boundary that the other two write.
 *
 * Without it the interleaving that matters is: a release reads the old boundary
 * and works out what to hand back, a grow blesses that very range (stopping
 * every thread in the process, the release's included) and raises the boundary
 * over it, and then the release resumes and discards what was just prepared.
 * TCG would go on to hand those pages out as usable, and the failure would
 * arrive as an illegal instruction fetch in generated code.
 *
 * Deadlock-free because a grow takes this *before* it traps: a holder stopped
 * by the trap is one the script resumes, and the script needs nothing from us.
 */
static QemuMutex tctish_cache_lock;

/*
 * Set when a shrink has left something worth handing back.
 *
 * Without it the release runs on every flush and tries to give back the whole
 * unused tail -- under Dynamic, most of two gigabytes, from the first flush of
 * the boot. Those pages have never been touched and have nothing resident to
 * return, so the work is futile even where the kernel permits it.
 */
static bool tctish_release_pending;

/*
 * Where the usable part ended before the shrink that is waiting to be paid.
 *
 * The far edge of what there is to give back. Everything past it has never been
 * prepared and so has never been touched: lazy anonymous pages with nothing
 * resident behind them, which cost nothing to keep and return nothing when
 * released.
 */
static size_t tctish_release_upto;

/*
 * Set by tctish_code_cache_release_all(): the release waiting to be paid starts
 * from the prologue rather than from the usable boundary. See there.
 */
static bool tctish_release_everything;

/*
 * Set once any page has been dropped from read-execute to read-write.
 *
 * Under TXM that is for good. Measured on device: the executable alias of
 * those pages comes back with a maximum protection of read-write, so
 * mprotect() cannot make it executable again; and
 * the alias itself is permanent, so it cannot be replaced either -- an
 * overwriting mach_vm_remap() answers KERN_PROTECTION_FAILURE, and munmap()
 * answers success but leaves the mapping where it was. Growing past a release
 * is therefore impossible there until the next launch.
 */
static bool tctish_ever_unprotected;

/*
 * Whether everything after the buffer's first page is purgeable, in pieces of
 * TCTISH_PURGEABLE_PIECE (tctish_alloc_purgeable()), under TXM only.
 *
 * What makes releasing survivable there. Emptying a purgeable object discards
 * its pages however many views map them, and changes neither view's protection
 * -- so the executable alias is never made writable, its addresses keep their
 * executability, and the debugger can prepare them again exactly as it
 * prepares a stretch it has never seen. That goes for a release of everything
 * while parked and for an ordinary shrink alike, so a shrunk cache can grow
 * again.
 *
 * In pieces because emptying is all or nothing per object: a shrink empties
 * every piece lying wholly past its boundary, and keeps the one it cuts
 * through.
 */
static bool tctish_purgeable;
#define TCTISH_PURGEABLE_PIECE (32 * MiB)

/*
 * Set by tctish_code_cache_release_all() and cleared once a flush has paid it
 * out, whatever came of it. What the app waits on before preparing the cache
 * again. Not the attempt count, which an ordinary shrink's flush moves too.
 */
static bool tctish_release_all_outstanding;

/*
 * Set when a release of everything has actually lowered the usable boundary,
 * and cleared by the next grow, which prepares what it lowered.
 *
 * With either flag set the machine must not run: TCG's regions still reach
 * past the boundary (region.available can't go below a region per vCPU), so
 * the first translation would land in pages that were emptied and, under TXM,
 * aren't executable. QEMU refuses `cont` and `unpark` meanwhile, rather than
 * trusting everyone who might start the machine to know. See
 * tctish_code_cache_may_run().
 */
static bool tctish_needs_preparing;

/*
 * Rounds a range *inward* to whole pages, false if nothing is left.
 *
 * For giving memory up. A page that is only partly past the boundary is still
 * partly in use, and handing it back would take live code with it.
 */
static bool tctish_pages_within(char **start, size_t *length)
{
    uintptr_t page = qemu_real_host_page_size();
    uintptr_t begin = ROUND_UP((uintptr_t)*start, page);
    uintptr_t end = ((uintptr_t)*start + *length) & ~(page - 1);

    if (end <= begin) {
        return false;
    }

    *start = (char *)begin;
    *length = end - begin;
    return true;
}

/*
 * The chunk the app wants the code buffer brought into use in, in bytes.
 *
 * Zero -- the default, and what every other host does -- means all at once.
 * Carried in the environment rather than as an accelerator property because it
 * is the same decision as TCTISH_JIT_BLESS and travels the same way: the app
 * owns it, because the app is what arranges the debugger each chunk needs.
 */
static size_t G_GNUC_UNUSED tctish_requested_chunk(void)
{
    const char *value = getenv("TCTISH_CODE_CACHE_CHUNK");
    unsigned long mib;

    if (value == NULL || *value == '\0') {
        return 0;
    }

    mib = strtoul(value, NULL, 10);
    return (size_t)mib * MiB;
}

/*
 * This is an array of struct tcg_region_tree's, with padding.
 * We use void * to simplify the computation of region_trees[i]; each
 * struct is found every tree_size bytes.
 */
static void *region_trees;
static size_t tree_size;

bool in_code_gen_buffer(const void *p)
{
    /*
     * Much like it is valid to have a pointer to the byte past the
     * end of an array (so long as you don't dereference it), allow
     * a pointer to the byte past the end of the code gen buffer.
     */
    return (size_t)(p - region.start_aligned) <= region.total_size;
}

#if !defined(CONFIG_TCG_INTERPRETER) && !defined(CONFIG_TCG_THREADED_INTERPRETER)
static int host_prot_read_exec(void)
{
#if defined(CONFIG_LINUX) && defined(HOST_AARCH64) && defined(PROT_BTI)
    if (cpuinfo & CPUINFO_BTI) {
        return PROT_READ | PROT_EXEC | PROT_BTI;
    }
#endif
    return PROT_READ | PROT_EXEC;
}
#endif

#ifdef CONFIG_DEBUG_TCG
const void *tcg_splitwx_to_rx(void *rw)
{
    /* Pass NULL pointers unchanged. */
    if (rw) {
        g_assert(in_code_gen_buffer(rw));
        rw += tcg_splitwx_diff;
    }
    return rw;
}

void *tcg_splitwx_to_rw(const void *rx)
{
    /* Pass NULL pointers unchanged. */
    if (rx) {
        rx -= tcg_splitwx_diff;
        /* Assert that we end with a pointer in the rw region. */
        g_assert(in_code_gen_buffer(rx));
    }
    return (void *)rx;
}
#endif /* CONFIG_DEBUG_TCG */

/* compare a pointer @ptr and a tb_tc @s */
static int ptr_cmp_tb_tc(const void *ptr, const struct tb_tc *s)
{
    if (ptr >= s->ptr + s->size) {
        return 1;
    } else if (ptr < s->ptr) {
        return -1;
    }
    return 0;
}

static gint tb_tc_cmp(gconstpointer ap, gconstpointer bp, gpointer userdata)
{
    const struct tb_tc *a = ap;
    const struct tb_tc *b = bp;

    /*
     * When both sizes are set, we know this isn't a lookup.
     * This is the most likely case: every TB must be inserted; lookups
     * are a lot less frequent.
     */
    if (likely(a->size && b->size)) {
        if (a->ptr > b->ptr) {
            return 1;
        } else if (a->ptr < b->ptr) {
            return -1;
        }
        /* a->ptr == b->ptr should happen only on deletions */
        g_assert(a->size == b->size);
        return 0;
    }
    /*
     * All lookups have either .size field set to 0.
     * From the glib sources we see that @ap is always the lookup key. However
     * the docs provide no guarantee, so we just mark this case as likely.
     */
    if (likely(a->size == 0)) {
        return ptr_cmp_tb_tc(a->ptr, b);
    }
    return ptr_cmp_tb_tc(b->ptr, a);
}

static void tb_destroy(gpointer value)
{
    TranslationBlock *tb = value;
    qemu_spin_destroy(&tb->jmp_lock);
}

static void tcg_region_trees_init(void)
{
    size_t i;

    tree_size = ROUND_UP(sizeof(struct tcg_region_tree), qemu_dcache_linesize);
    region_trees = qemu_memalign(qemu_dcache_linesize, region.n * tree_size);
    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        qemu_mutex_init(&rt->lock);
        rt->tree = q_tree_new_full(tb_tc_cmp, NULL, NULL, tb_destroy);
    }
}

static struct tcg_region_tree *tc_ptr_to_region_tree(const void *p)
{
    size_t region_idx;

    /*
     * Like tcg_splitwx_to_rw, with no assert.  The pc may come from
     * a signal handler over which the caller has no control.
     */
    if (!in_code_gen_buffer(p)) {
        p -= tcg_splitwx_diff;
        if (!in_code_gen_buffer(p)) {
            return NULL;
        }
    }

    if (p < region.start_aligned) {
        region_idx = 0;
    } else {
        ptrdiff_t offset = p - region.start_aligned;

        if (offset > region.stride * (region.n - 1)) {
            region_idx = region.n - 1;
        } else {
            region_idx = offset / region.stride;
        }
    }
    return region_trees + region_idx * tree_size;
}

void tcg_tb_insert(TranslationBlock *tb)
{
    struct tcg_region_tree *rt = tc_ptr_to_region_tree(tb->tc.ptr);

    g_assert(rt != NULL);
    qemu_mutex_lock(&rt->lock);
    q_tree_insert(rt->tree, &tb->tc, tb);
    qemu_mutex_unlock(&rt->lock);
}

void tcg_tb_remove(TranslationBlock *tb)
{
    struct tcg_region_tree *rt = tc_ptr_to_region_tree(tb->tc.ptr);

    g_assert(rt != NULL);
    qemu_mutex_lock(&rt->lock);
    q_tree_remove(rt->tree, &tb->tc);
    qemu_mutex_unlock(&rt->lock);
}

/*
 * Find the TB 'tb' such that
 * tb->tc.ptr <= tc_ptr < tb->tc.ptr + tb->tc.size
 * Return NULL if not found.
 */
TranslationBlock *tcg_tb_lookup(uintptr_t tc_ptr)
{
    struct tcg_region_tree *rt = tc_ptr_to_region_tree((void *)tc_ptr);
    TranslationBlock *tb;
    struct tb_tc s = { .ptr = (void *)tc_ptr };

    if (rt == NULL) {
        return NULL;
    }

    qemu_mutex_lock(&rt->lock);
    tb = q_tree_lookup(rt->tree, &s);
    qemu_mutex_unlock(&rt->lock);
    return tb;
}

static void tcg_region_tree_lock_all(void)
{
    size_t i;

    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        qemu_mutex_lock(&rt->lock);
    }
}

static void tcg_region_tree_unlock_all(void)
{
    size_t i;

    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        qemu_mutex_unlock(&rt->lock);
    }
}

void tcg_tb_foreach(GTraverseFunc func, gpointer user_data)
{
    size_t i;

    tcg_region_tree_lock_all();
    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        q_tree_foreach(rt->tree, func, user_data);
    }
    tcg_region_tree_unlock_all();
}

size_t tcg_nb_tbs(void)
{
    size_t nb_tbs = 0;
    size_t i;

    tcg_region_tree_lock_all();
    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        nb_tbs += q_tree_nnodes(rt->tree);
    }
    tcg_region_tree_unlock_all();
    return nb_tbs;
}

static void tcg_region_tree_reset_all(void)
{
    size_t i;

    tcg_region_tree_lock_all();
    for (i = 0; i < region.n; i++) {
        struct tcg_region_tree *rt = region_trees + i * tree_size;

        /* Increment the refcount first so that destroy acts as a reset */
        q_tree_ref(rt->tree);
        q_tree_destroy(rt->tree);
    }
    tcg_region_tree_unlock_all();
}

static void tcg_region_bounds(size_t curr_region, void **pstart, void **pend)
{
    void *start, *end;

    start = region.start_aligned + curr_region * region.stride;
    end = start + region.size;

    if (curr_region == 0) {
        start = region.after_prologue;
    }
    /* The final region may have a few extra pages due to earlier rounding. */
    if (curr_region == region.n - 1) {
        end = region.start_aligned + region.total_size;
    }

    *pstart = start;
    *pend = end;
}

/*
 * How many whole regions fit inside the first `bytes` of the buffer.
 *
 * Whole ones only: a region that runs past the limit contains memory that has
 * not been prepared, and a vCPU handed it would translate into pages that fault
 * the moment they are executed.
 */
static size_t tcg_regions_within(size_t bytes)
{
    void *limit = region.start_aligned + bytes;
    size_t n;

    for (n = 0; n < region.n; n++) {
        void *start, *end;

        tcg_region_bounds(n, &start, &end);
        if (end > limit) {
            break;
        }
    }

    return n;
}

#ifdef MADV_FREE_REUSABLE
/*
 * Gives `advice` for the writable view of the buffer in use between byte
 * offsets `from` and `to`, region by region: around the guard page that ends
 * each one, and in whole pages only. Returns 0, or the first errno.
 *
 * Darwin refuses MADV_FREE_REUSABLE (and MADV_FREE_REUSE) for the whole call,
 * EPERM, as soon as one page in the range isn't writable -- and a guard page
 * never is. Over a range that crosses regions, which a release nearly always
 * does, one call gave nothing back at all.
 */
static int tctish_madvise_regions(size_t from, size_t to, int advice)
{
    char *rw = region.start_aligned;
    int err = 0;

    for (size_t i = 0; i < region.n; i++) {
        void *start, *end;
        char *s;
        size_t length;

        tcg_region_bounds(i, &start, &end);
        s = MAX((char *)start, rw + from);
        if (MIN((char *)end, rw + to) <= s) {
            continue;
        }
        length = MIN((char *)end, rw + to) - s;

        if (tctish_pages_within(&s, &length) &&
            madvise(s, length, advice) != 0 && err == 0) {
            err = errno;
        }
    }

    return err;
}
#endif

static void tcg_region_assign(TCGContext *s, size_t curr_region)
{
    void *start, *end;

    tcg_region_bounds(curr_region, &start, &end);

    s->code_gen_buffer = start;
    s->code_gen_ptr = start;
    s->code_gen_buffer_size = end - start;
    s->code_gen_highwater = end - TCG_HIGHWATER;
}

static bool tcg_region_alloc__locked(TCGContext *s)
{
    /*
     * Against .available rather than .n, so that a buffer only partly prepared
     * runs out early and flushes rather than handing out memory that cannot be
     * executed. When all of it is usable the two are equal and this is the
     * check it has always been.
     */
    if (region.current >= region.available) {
        return false;
    }
    tcg_region_assign(s, region.current);
    region.current++;
    return true;
}

/*
 * Request a new region once the one in use has filled up.
 * Returns true on success.
 */
bool tcg_region_alloc(TCGContext *s)
{
    bool ok;
    /* read the region size now; alloc__locked will overwrite it on success */
    size_t size_full = s->code_gen_buffer_size;

    qemu_mutex_lock(&region.lock);
    ok = tcg_region_alloc__locked(s);
    if (ok) {
        region.agg_size_full += size_full - TCG_HIGHWATER;
    }
    qemu_mutex_unlock(&region.lock);
    return ok;
}

/*
 * Perform a context's first region allocation.
 * This function does _not_ increment region.agg_size_full.
 */
static void tcg_region_initial_alloc__locked(TCGContext *s)
{
    bool ok = tcg_region_alloc__locked(s);
    g_assert(ok);
}

void tcg_region_thread_initial_alloc(TCGContext *s)
{
    bool ok;

    qemu_mutex_lock(&region.lock);
    ok = tcg_region_alloc__locked(s);
    qemu_mutex_unlock(&region.lock);

    /*
     * A vCPU hotplug may happen at any time.  When the new thread is
     * started, the region pool may be exhausted.  At this point in
     * the new thread call stack, we are not in a position to fix this.
     * Leave code_gen_ptr NULL, so that this thread's first call to
     * tcg_tb_alloc() returns NULL, so that the translator performs
     * a tb_flush() and retry.
     *
     * During the tb_flush(), tcg_region_reset_all() will assign a
     * new region to all contexts, including this one.
     */
    if (!ok) {
        s->code_gen_buffer = NULL;
        s->code_gen_ptr = NULL;
        s->code_gen_buffer_size = 0;
        s->code_gen_highwater = NULL;
    }
}

/* Call from a safe-work context */
void tcg_region_reset_all(void)
{
    unsigned int n_ctxs = qatomic_read(&tcg_cur_ctxs);
    unsigned int i;

    qemu_mutex_lock(&region.lock);
    region.current = 0;
    region.agg_size_full = 0;

    for (i = 0; i < n_ctxs; i++) {
        TCGContext *s = qatomic_read(&tcg_ctxs[i]);
        tcg_region_initial_alloc__locked(s);
    }
    qemu_mutex_unlock(&region.lock);

    tcg_region_tree_reset_all();
}

static size_t tcg_n_regions(size_t tb_size, unsigned max_threads)
{
#ifdef CONFIG_USER_ONLY
    return 1;
#else
    size_t n_regions;

    /*
     * It is likely that some vCPUs will translate more code than others,
     * so we first try to set more regions than threads, with those regions
     * being of reasonable size. If that's not possible we make do by evenly
     * dividing the code_gen_buffer among the vCPUs.
     *
     * Use a single region if all we have is one vCPU thread.
     */
    if (max_threads == 1) {
        return 1;
    }

    /*
     * Try to have more regions than threads, with each region being >= 2 MB.
     * If we can't, then just allocate one region per vCPU thread.
     */
    n_regions = tb_size / (2 * MiB);
    if (n_regions <= max_threads) {
        return max_threads;
    }
    return MIN(n_regions, max_threads * 8);
#endif
}

/*
 * The fewest regions that can be in use at once without a flush failing.
 *
 * tcg_region_reset_all() gives every context a region and asserts if one cannot
 * be had, so dropping below this would turn a full code cache into a crash.
 *
 * One per thread that translates: tcg_region_init() is told how many there
 * can be, which is the vCPU count under MTTCG and one otherwise.
 */
static size_t tcg_min_regions(unsigned max_threads)
{
#ifdef CONFIG_USER_ONLY
    return 1;
#else
    return max_threads;
#endif
}

/*
 * Minimum size of the code gen buffer.  This number is randomly chosen,
 * but not so small that we can't have a fair number of TB's live.
 *
 * Maximum size, MAX_CODE_GEN_BUFFER_SIZE, is defined in tcg-target.h.
 * Unless otherwise indicated, this is constrained by the range of
 * direct branches on the host cpu, as used by the TCG implementation
 * of goto_tb.
 */
#define MIN_CODE_GEN_BUFFER_SIZE     (1 * MiB)

#ifdef CONFIG_USER_ONLY
/*
 * As user-mode emulation typically means running multiple instances
 * of the translator don't go too nuts with our default code gen
 * buffer lest we make things too hard for the OS.
 */
#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (128 * MiB)
#else
/*
 * We expect most system emulation to run one or two guests per host.
 * Users running large scale system emulation may want to tweak their
 * runtime setup via the tb-size control on the command line.
 */
#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (1 * GiB)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE \
  (DEFAULT_CODE_GEN_BUFFER_SIZE_1 < MAX_CODE_GEN_BUFFER_SIZE \
   ? DEFAULT_CODE_GEN_BUFFER_SIZE_1 : MAX_CODE_GEN_BUFFER_SIZE)

/*
 * A code buffer as alloc_code_gen_buffer() mapped it, before it is the one in
 * use: tcg_region_take_buffer() makes it so.
 *
 * Filled in rather than written straight into the region state, so that a
 * buffer can be mapped -- and on iOS, prepared by a debugger -- while another
 * is in use and the vCPUs run in it.
 */
typedef struct TCGCodeBuffer {
    void *start;            /* region.start_aligned: the writable view */
    size_t size;            /* region.total_size, as mapped */
    ptrdiff_t splitwx_diff; /* tcg_splitwx_diff */

    /* tctish_usable_bytes, tctish_chunked and tctish_purgeable, for it. */
    size_t usable_bytes;
    bool chunked;
    bool purgeable;

    /* Under TXM: mapped for blessing, but no debugger was there to bless it. */
    bool unprepared;
} TCGCodeBuffer;

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]
    __attribute__((aligned(CODE_GEN_ALIGN)));

static int alloc_code_gen_buffer(size_t tb_size, int splitwx, bool tcti,
                                 TCGCodeBuffer *cb, Error **errp)
{
    void *buf, *end;
    size_t size;

    if (splitwx > 0) {
        error_setg(errp, "jit split-wx not supported");
        return -1;
    }

    /* page-align the beginning and end of the buffer */
    buf = static_code_gen_buffer;
    end = static_code_gen_buffer + sizeof(static_code_gen_buffer);
    buf = QEMU_ALIGN_PTR_UP(buf, qemu_real_host_page_size());
    end = QEMU_ALIGN_PTR_DOWN(end, qemu_real_host_page_size());

    size = end - buf;

    /* Honor a command-line option limiting the size of the buffer.  */
    if (size > tb_size) {
        size = QEMU_ALIGN_DOWN(tb_size, qemu_real_host_page_size());
    }

    cb->start = buf;
    cb->size = size;

    return PROT_READ | PROT_WRITE;
}
#elif defined(_WIN32)
static int alloc_code_gen_buffer(size_t size, int splitwx, bool tcti,
                                 TCGCodeBuffer *cb, Error **errp)
{
    void *buf;

    if (splitwx > 0) {
        error_setg(errp, "jit split-wx not supported");
        return -1;
    }

    buf = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT,
                             PAGE_EXECUTE_READWRITE);
    if (buf == NULL) {
        error_setg_win32(errp, GetLastError(),
                         "allocate %zu bytes for jit buffer", size);
        return false;
    }

    cb->start = buf;
    cb->size = size;

    return PROT_READ | PROT_WRITE | PROT_EXEC;
}
#else
static int alloc_code_gen_buffer_anon(size_t size, int prot,
                                      int flags, TCGCodeBuffer *cb,
                                      Error **errp)
{
    void *buf;

    buf = mmap(NULL, size, prot, flags, -1, 0);
    if (buf == MAP_FAILED) {
        error_setg_errno(errp, errno,
                         "allocate %zu bytes for jit buffer", size);
        return -1;
    }

    cb->start = buf;
    cb->size = size;
    return prot;
}

#if !defined(CONFIG_TCG_INTERPRETER) && !defined(CONFIG_TCG_THREADED_INTERPRETER)
#ifdef CONFIG_POSIX
#include "qemu/memfd.h"

static int alloc_code_gen_buffer_splitwx_memfd(size_t size, TCGCodeBuffer *cb,
                                               Error **errp)
{
    void *buf_rw = NULL, *buf_rx = MAP_FAILED;
    int fd = -1;

    buf_rw = qemu_memfd_alloc("tcg-jit", size, 0, &fd, errp);
    if (buf_rw == NULL) {
        goto fail;
    }

    buf_rx = mmap(NULL, size, host_prot_read_exec(), MAP_SHARED, fd, 0);
    if (buf_rx == MAP_FAILED) {
        error_setg_errno(errp, errno,
                         "failed to map shared memory for execute");
        goto fail;
    }

    close(fd);
    cb->start = buf_rw;
    cb->size = size;
    cb->splitwx_diff = buf_rx - buf_rw;

    return PROT_READ | PROT_WRITE;

 fail:
    /* buf_rx is always equal to MAP_FAILED here and does not require cleanup */
    if (buf_rw) {
        munmap(buf_rw, size);
    }
    if (fd >= 0) {
        close(fd);
    }
    return -1;
}
#endif /* CONFIG_POSIX */

#ifdef CONFIG_DARWIN
#include <mach/mach.h>

#include <mach/vm_purgable.h>

extern kern_return_t mach_vm_purgable_control(vm_map_t target_task,
                                              mach_vm_address_t address,
                                              vm_purgable_t control,
                                              int *state);

extern kern_return_t mach_vm_remap(vm_map_t target_task,
                                   mach_vm_address_t *target_address,
                                   mach_vm_size_t size,
                                   mach_vm_offset_t mask,
                                   int flags,
                                   vm_map_t src_task,
                                   mach_vm_address_t src_address,
                                   boolean_t copy,
                                   vm_prot_t *cur_protection,
                                   vm_prot_t *max_protection,
                                   vm_inherit_t inheritance);

#include <TargetConditionals.h>
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
#include <sys/types.h>
#include <sys/sysctl.h>
/*
 * Whether the app asked us to hand JIT regions to an attached debugger.
 *
 * The decision belongs to the app, not to QEMU, because it is the app that
 * arranges for the debugger to be attached with the script that speaks this
 * protocol. A trap with no script listening kills the process.
 *
 * The app keys this off TXM presence, matching StikJIT's own gate, so the two
 * cannot disagree. Upstream tests __builtin_available(iOS 26) here instead,
 * which answers a different question: whether the OS *might* need blessing,
 * not whether anything is listening to do it.
 *
 * For a buffer of native code, which is all that is ever split, and so all the
 * split allocator below ever maps.
 */
static bool jit_region_blessing_wanted(void)
{
    const char *requested = getenv("TCTISH_JIT_BLESS");

    return requested != NULL && requested[0] == '1';
}

/*
 * Whether the buffer in use is one to bless. TCTI executes nothing it writes,
 * so in a hybrid it has nothing to bless.
 */
static bool jit_region_blessing_requested(void)
{
    return !tcg_tcti_active() && jit_region_blessing_wanted();
}

static int is_debugger_attached(void)
{
    int mib[4];
    struct kinfo_proc info;
    size_t size;

    info.kp_proc.p_flag = 0;

    /* Initialize MIB for sysctl call */
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, NULL, 0) == -1) {
        return 0; // sysctl failed, be conservative
    }

    /* P_TRACED means the process is being debugged */
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/*
 * The two calls of StikJIT's universal protocol: x16 selects the operation,
 * brk #0xf00d traps into the attached script, and the answer comes back in x0.
 *
 * Naked because the protocol is written in terms of registers. The arguments
 * have to reach the trap in x0 and x1 exactly as the caller passed them, and
 * the answer has to leave in x0 -- a prologue that spilled either would be
 * talking to the script about the wrong memory.
 *
 * This replaces upstream's one-way brk #0x69, which cannot report where the
 * region ended up and has no way to tell the script it is finished.
 */
__attribute__((noinline, optnone, naked))
static void *jit26_prepare_region(void *addr, size_t len)
{
    asm ("mov x16, #1\n"
         "brk #0xf00d\n"
         "ret");
}

/*
 * Releases the script once every region it will ever be asked about exists.
 *
 * Not merely tidy: the script sits in its stop loop until it sees this, so
 * whatever is driving it -- for us, a blocked helper extension -- never returns
 * without it. Nothing mapped after this point can be prepared.
 */
__attribute__((noinline, optnone, naked))
static void jit26_detach(void)
{
    asm ("mov x16, #0\n"
         "brk #0xf00d\n"
         "ret");
}
#endif

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
/*
 * The purgeable piece holding byte `offset` of the buffer, as offsets. The
 * first starts after the buffer's first page, and the last ends with the
 * buffer; see tctish_purgeable.
 */
static void tctish_piece_at(size_t offset, size_t size, size_t *start,
                            size_t *end)
{
    size_t page = qemu_real_host_page_size();

    *start = MAX(QEMU_ALIGN_DOWN(offset, TCTISH_PURGEABLE_PIECE), page);
    *end = MIN(QEMU_ALIGN_DOWN(offset, TCTISH_PURGEABLE_PIECE) +
               TCTISH_PURGEABLE_PIECE, size);
}

/*
 * Maps the buffer for blessing as purgeable pieces behind an ordinary first
 * page, and returns whether it could. See tctish_purgeable.
 *
 * The first page is apart because it holds the prologue, which has to survive
 * every release. Everything is mapped as alloc_code_gen_buffer_anon() would
 * map it otherwise, read-execute from the start; the purgeable flag travels in
 * mmap()'s descriptor, as Darwin takes VM flags for anonymous memory. On any
 * refusal nothing is left mapped and the caller maps the ordinary way.
 */
static bool tctish_alloc_purgeable(size_t size, TCGCodeBuffer *cb)
{
    size_t page = qemu_real_host_page_size();
    size_t start, end;
    char *buf;

    buf = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (buf == MAP_FAILED) {
        error_report("code cache: no buffer to make purgeable (%s)",
                     strerror(errno));
        return false;
    }

    for (size_t offset = page; offset < size; offset = end) {
        tctish_piece_at(offset, size, &start, &end);

        if (mmap(buf + start, end - start, PROT_READ | PROT_EXEC,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, VM_FLAGS_PURGABLE,
                 0) == MAP_FAILED) {
            error_report("code cache: no purgeable piece at %zu MiB (%s); "
                         "releases under TXM will be refused or final",
                         (size_t)(start / MiB), strerror(errno));
            munmap(buf, size);
            return false;
        }
    }

    info_report("code cache: purgeable after the first page, so it can be "
                "released and prepared again");
    cb->start = buf;
    cb->size = size;
    return true;
}
#endif

static int alloc_code_gen_buffer_splitwx_vmremap(size_t size, TCGCodeBuffer *cb,
                                                 Error **errp)
{
    kern_return_t ret;
    mach_vm_address_t buf_rw, buf_rx;
    vm_prot_t cur_prot, max_prot;
    int orig_prot = PROT_READ | PROT_WRITE;

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    /* TXM requires the region to start out executable. */
    if (jit_region_blessing_wanted()) {
        orig_prot = PROT_READ | PROT_EXEC;
        cb->purgeable = tctish_alloc_purgeable(size, cb);
    }
#endif

    /* Negative on failure, not zero: upstream's `!` never caught one. */
    if (!cb->purgeable &&
        alloc_code_gen_buffer_anon(size, orig_prot,
                                   MAP_PRIVATE | MAP_ANONYMOUS, cb, errp) < 0) {
        return -1;
    }

    buf_rw = (mach_vm_address_t)cb->start;
    buf_rx = 0;
    ret = mach_vm_remap(mach_task_self(),
                        &buf_rx,
                        size,
                        0,
                        VM_FLAGS_ANYWHERE,
                        mach_task_self(),
                        buf_rw,
                        false,
                        &cur_prot,
                        &max_prot,
                        VM_INHERIT_NONE);
    if (ret != KERN_SUCCESS) {
        /* TODO: Convert "ret" to a human readable error message. */
        error_setg(errp, "vm_remap for jit splitwx failed");
        munmap((void *)buf_rw, size);
        return -1;
    }

    if (mprotect((void *)buf_rx, size, host_prot_read_exec()) != 0) {
        error_setg_errno(errp, errno, "mprotect for jit splitwx");
        munmap((void *)buf_rx, size);
        munmap((void *)buf_rw, size);
        return -1;
    }

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (jit_region_blessing_wanted()) {
        /*
         * Sampled once, because everything below has to agree about whether a
         * script is listening: trapping with none attached kills the process,
         * and a script left waiting for its detach hangs the helper driving it.
         */
        bool attached = is_debugger_attached();
        bool prepared = true;
        size_t chunk = tctish_requested_chunk();
        size_t first = (chunk != 0 && chunk < size) ? chunk : size;

        if (attached) {
            /*
             * The script prepares the RX mapping and answers with its address.
             * It is entitled to answer with a different one -- that is what
             * passing NULL asks it to do -- but buf_rw is an alias of the
             * region we mapped ourselves, so anything else would leave the two
             * halves of the split mapping pointing at different memory.
             */
            void *blessed = jit26_prepare_region((void *)buf_rx, first);

            if (blessed != (void *)buf_rx) {
                error_setg(errp, "debugger prepared %p, not the jit region %p",
                           blessed, (void *)buf_rx);
                prepared = false;
            }
        }

        /* finally mark the read-write portion as RW */
        if (prepared && mprotect((void *)buf_rw, size,
                                 PROT_READ | PROT_WRITE) != 0) {
            error_setg_errno(errp, errno, "mprotect for jit splitwx (rw)");
            prepared = false;
        }

        /*
         * Let the script go, and with it the helper that is blocked driving it.
         * Anything still to be prepared gets a helper of its own later, which is
         * the whole point of chunking: one short freeze now instead of one long
         * one. Issued on the failure paths too, or nothing would ever return.
         */
        if (attached) {
            jit26_detach();
        }

        if (!prepared) {
            munmap((void *)buf_rx, size);
            munmap((void *)buf_rw, size);
            return -1;
        }

        /*
         * Only what was prepared may be executed, so only that much is offered
         * to TCG. The rest is mapped and writable but has never been through a
         * debugger, and would fault the instant it was jumped to.
         *
         * With nothing attached nothing was prepared and nothing can be, so a
         * limit would buy nothing: leave the buffer whole and let JIT fail the
         * way it was already going to.
         */
        cb->usable_bytes = attached ? first : size;
        cb->chunked = attached && first < size;
        cb->unprepared = !attached;
    }
#endif

    cb->splitwx_diff = buf_rx - buf_rw;
    return PROT_READ | PROT_WRITE;
}
#endif /* CONFIG_DARWIN */
#endif /* !CONFIG_TCG_INTERPRETER && !CONFIG_TCG_THREADED_INTERPRETER */

static int alloc_code_gen_buffer_splitwx(size_t size, TCGCodeBuffer *cb,
                                         Error **errp)
{
#if !defined(CONFIG_TCG_INTERPRETER) && !defined(CONFIG_TCG_THREADED_INTERPRETER)
# ifdef CONFIG_DARWIN
    return alloc_code_gen_buffer_splitwx_vmremap(size, cb, errp);
# endif
# ifdef CONFIG_POSIX
    return alloc_code_gen_buffer_splitwx_memfd(size, cb, errp);
# endif
#endif
    error_setg(errp, "jit split-wx not supported");
    return -1;
}

/*
 * Maps a code buffer of `size` bytes for TCTI (tcti) or for native code, and
 * describes it in *cb; returns the protection it was mapped with, or -1.
 *
 * Touches nothing else -- not the region state, not tcg_splitwx_diff, not which
 * backend is active -- so it may run while another buffer is in use. On iOS
 * under TXM it also has the attached debugger prepare the buffer, or its first
 * chunk, which stops every thread in the process until the debugger is done,
 * but changes nothing they see.
 */
static int alloc_code_gen_buffer(size_t size, int splitwx, bool tcti,
                                 TCGCodeBuffer *cb, Error **errp)
{
    ERRP_GUARD();
    int prot, flags;

    *cb = (TCGCodeBuffer) { };

    if (splitwx) {
        prot = alloc_code_gen_buffer_splitwx(size, cb, errp);
        if (prot >= 0) {
            return prot;
        }
        /*
         * If splitwx force-on (1), fail;
         * if splitwx default-on (-1), fall through to splitwx off.
         */
        if (splitwx > 0) {
            return -1;
        }
        error_free_or_abort(errp);
        *cb = (TCGCodeBuffer) { };
    }

    /*
     * macOS 11.2 has a bug (Apple Feedback FB8994773) in which mprotect
     * rejects a permission change from RWX -> NONE when reserving the
     * guard pages later.  We can go the other way with the same number
     * of syscalls, so always begin with PROT_NONE.
     */
    prot = PROT_NONE;
    flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(CONFIG_DARWIN) && !defined(CONFIG_TCG_THREADED_INTERPRETER)
    /*
     * Applicable to both iOS and macOS (Apple Silicon). TCTI's code buffer
     * is data, never executed, and it exists for hosts that may not map
     * JIT memory at all -- where asking for MAP_JIT fails the mmap.
     */
    if (!splitwx && !tcti) {
        flags |= MAP_JIT;
    }
#endif

    return alloc_code_gen_buffer_anon(size, prot, flags, cb, errp);
}
#endif /* USE_STATIC_CODE_GEN_BUFFER, WIN32, POSIX */

/*
 * Makes a buffer that alloc_code_gen_buffer() mapped the code buffer, for
 * tcg_region_init() to partition.
 */
static void tcg_region_take_buffer(const TCGCodeBuffer *cb)
{
    region.start_aligned = cb->start;
    region.total_size = cb->size;
    tcg_splitwx_diff = cb->splitwx_diff;
    tctish_usable_bytes = cb->usable_bytes;
    tctish_chunked = cb->chunked;
    tctish_purgeable = cb->purgeable;
}

/*
 * Partitions the code buffer that tcg_region_take_buffer() has just made the
 * one in use into regions, with guard pages between them. have_prot is what
 * the buffer was mapped with.
 *
 * From tcg_region_init(), and in a hybrid of two backends again for the other
 * one's buffer, the first time a switch makes it the one in use.
 */
static void tcg_region_layout(size_t tb_size, unsigned max_threads, int have_prot)
{
    const size_t page_size = qemu_real_host_page_size();
    size_t region_size;
    int need_prot;

    /*
     * How much of the buffer to start with, in bytes; zero for all of it, which
     * is what everything except a chunk-blessed iOS JIT wants. Local because
     * the regions are laid out once and never move -- making more of the buffer
     * usable later is raising a count, not re-partitioning.
     */
    size_t initial_usable;

    /*
     * What the allocator managed to prepare, now that it has run.
     *
     * Only a chunk-blessed iOS JIT sets these; every other host -- TCTI
     * included, which never blesses because it never executes what it
     * generates -- leaves tctish_usable_bytes at zero, and a zero here would
     * read as "none of the buffer is usable" rather than "no limit". The
     * clamp below the partitioning settles that; this hands the region sizing
     * the byte count it has to fit the vCPUs inside.
     */
    initial_usable = tctish_chunked ? tctish_usable_bytes : 0;

    /* Request large pages for the buffer and the splitwx.  */
    qemu_madvise(region.start_aligned, region.total_size, QEMU_MADV_HUGEPAGE);
    if (tcg_splitwx_diff) {
        qemu_madvise(region.start_aligned + tcg_splitwx_diff,
                     region.total_size, QEMU_MADV_HUGEPAGE);
    }

    /*
     * Make region_size a multiple of page_size, using aligned as the start.
     * As a result of this we might end up with a few extra pages at the end of
     * the buffer; we will assign those to the last region.
     */
    region.n = tcg_n_regions(tb_size, max_threads);

    /*
     * If only part of the buffer starts out usable, the regions have to be small
     * enough that every vCPU can be given one from inside that part.
     *
     * Getting this wrong is not a performance problem. A flush hands one region
     * to each context and asserts if it cannot, so too few regions crashes at
     * the first flush -- and papering over that by handing out regions past the
     * usable boundary is far worse, because those are pages a debugger has never
     * prepared and the failure is an illegal instruction fetch in generated
     * code, thousands of instructions from anything that explains it.
     *
     * So the regions are made to fit instead. Splitting the buffer more finely
     * costs a slightly larger region tree and nothing else.
     */
    if (initial_usable != 0) {
        size_t needed = tcg_min_regions(max_threads);

        /* The hard floor: every vCPU must hold one from inside the usable part. */
        size_t least = DIV_ROUND_UP(tb_size * needed, initial_usable);

        /*
         * And then some. At exactly the floor every vCPU holds the only region
         * it will ever get, so the first one to fill up takes the whole cache
         * down with it -- the effective size becomes whatever the busiest thread
         * fits in a quarter of the buffer, and the rest is never touched. Four
         * apiece leaves room to move on without a flush, which is what regions
         * are for.
         */
        size_t wanted = least * 4;

        /* Not past where a region stops being worth having; QEMU's own floor. */
        size_t finest = MAX(least, tb_size / (2 * MiB));

        region.n = MAX(region.n, MIN(wanted, finest));
    }
    region_size = tb_size / region.n;
    region_size = QEMU_ALIGN_DOWN(region_size, page_size);

    /* A region must have at least 2 pages; one code, one guard */
    g_assert(region_size >= 2 * page_size);
    region.stride = region_size;

    /* Reserve space for guard pages. */
    region.size = region_size - page_size;
    region.total_size -= page_size;

    /*
     * Settle the boundary against the buffer as partitioned.
     *
     * Two things are being fixed. A host that did not chunk has no boundary at
     * all and must read as "all of it", not as zero -- otherwise
     * tctish_code_cache_grow() would see nothing usable and set the limit *down*
     * to whatever it was asked for. And total_size has just lost its final guard
     * page, so a blessing measured against the whole allocation would sit a page
     * past anything TCG can reach.
     */
    if (!tctish_chunked || tctish_usable_bytes > region.total_size) {
        tctish_usable_bytes = region.total_size;
    }

    /*
     * How much may be translated into to begin with. All of it unless someone
     * has said otherwise, and never less than the vCPUs can hold between them
     * however small a chunk was asked for -- a cache too small to give every
     * context a region is not a small cache, it is a failed assertion.
     */
    region.min_available = MIN(tcg_min_regions(max_threads), region.n);
    region.available = region.n;
    if (initial_usable != 0) {
        region.available = tcg_regions_within(initial_usable);
    }

    /*
     * Never the MAX of the two. The count above is a hard safety limit -- past
     * it lie pages no debugger has prepared -- so raising it to satisfy the
     * floor would trade an assertion here for an illegal instruction fetch
     * later. The region sizing above exists to make both true at once; if it
     * ever fails to, that is a bug to hear about at startup.
     */
    g_assert(region.available >= region.min_available);

    /*
     * The first region will be smaller than the others, via the prologue,
     * which has yet to be allocated.  For now, the first region begins at
     * the page boundary.
     */
    region.after_prologue = region.start_aligned;

    /*
     * Set guard pages in the rw buffer, as that's the one into which
     * buffer overruns could occur.  Do not set guard pages in the rx
     * buffer -- let that one use hugepages throughout.
     * Work with the page protections set up with the initial mapping.
     */
    need_prot = PROT_READ | PROT_WRITE;
#if !defined(CONFIG_TCG_INTERPRETER) && !defined(CONFIG_TCG_THREADED_INTERPRETER)
    if (tcg_splitwx_diff == 0 && !tcg_tcti_active()) {
        need_prot |= host_prot_read_exec();
    }
#endif
    for (size_t i = 0, n = region.n; i < n; i++) {
        void *start, *end;

        tcg_region_bounds(i, &start, &end);
        if (have_prot != need_prot) {
            int rc;

            if (need_prot == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
                rc = qemu_mprotect_rwx(start, end - start);
            } else if (need_prot == (PROT_READ | PROT_WRITE)) {
                rc = qemu_mprotect_rw(start, end - start);
            } else {
#ifdef CONFIG_POSIX
                rc = mprotect(start, end - start, need_prot);
                if (rc) {
                    error_report("mprotect of jit buffer: %s",
                                 strerror(errno));
                }
#else
                g_assert_not_reached();
#endif
            }
            if (rc) {
                exit(1);
            }
        }
        if (have_prot != 0) {
            /* Guard pages are nice for bug detection but are not essential. */
            (void)qemu_mprotect_none(end, page_size);
        }
    }
}

/*
 * Whether this build hands JIT pages to a debugger before they can be executed.
 *
 * Exactly the condition the helpers above are compiled under. TCTI never
 * generates anything the host executes directly, so it never blesses -- which
 * means its code buffer is usable in full from the start and has nothing to
 * grow.
 */
#if !defined(CONFIG_TCG_INTERPRETER) && !defined(CONFIG_TCG_THREADED_INTERPRETER) \
    && defined(CONFIG_DARWIN) && defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE \
    && !TARGET_OS_SIMULATOR
#define TCTISH_BLESSING_POSSIBLE 1
#else
#define TCTISH_BLESSING_POSSIBLE 0
#endif

#ifdef CONFIG_TCG_HYBRID_RUNTIME
static void tctish_release_unused__locked(void);

/*
 * A hybrid of two backends has a code buffer for each, as each needs its own
 * kind of memory: TCTI's holds data, the native backend's holds code the host
 * executes (MAP_JIT, maybe split, and under TXM prepared by a debugger). Only
 * the active one is in use; the other is parked as it was left -- mapped,
 * partitioned, prepared as far as it was -- so that switching back maps and
 * prepares nothing again.
 *
 * Each is mapped by tcg_region_hybrid_prepare() before the first switch to it,
 * which for the native backend's is the app's to call while the guest runs:
 * under TXM, preparing it stops the process for as long as the debugger takes,
 * and the switch itself, with every vCPU stopped, should take milliseconds.
 * It is partitioned at the first switch to it, and keeps that partitioning.
 */
typedef struct TCGHybridBuffer {
    TCGCodeBuffer cb;       /* as mapped; .start is NULL until it is */
    int prot;               /* what it was mapped with */
    bool laid_out;          /* partitioned, and the fields below set */

    /*
     * Its partitioning, as region holds it while in use. The same every time,
     * because its guard pages are where the first one put them -- and macOS
     * will not make MAP_JIT pages that have been executable RWX a second time,
     * so they could not be moved -- and because a buffer prepared in chunks
     * has regions sized to fit its first one (tcg_region_layout()).
     */
    size_t n, size, stride, total_size, min_available;
    void *trees;            /* region_trees, one per region, so its own */

    /* tctish_ever_unprotected, for it; the rest of its state is in cb. */
    bool ever_unprotected;

    /*
     * Emptied while parked, by tcg_region_hybrid_release_native(), and to be
     * prepared again before it is used: see there.
     */
    bool released;
} TCGHybridBuffer;

static struct {
    /*
     * Over mapping, preparing and releasing a buffer, which the app's thread
     * does, and switching, which safe work does and holds from preparing the
     * buffer switched to until it is in use: a switch waits for a buffer
     * still being prepared, and a release cannot take one from under it.
     * Taken before tctish_cache_lock.
     */
    QemuMutex lock;
    TCGHybridBuffer buf[2]; /* [tcti] */
    size_t tb_size;
    int splitwx;
    unsigned max_threads;
} tcg_region_hybrid;

static void tcg_region_hybrid_init(size_t tb_size, int splitwx,
                                   unsigned max_threads,
                                   const TCGCodeBuffer *cb, int prot)
{
    qemu_mutex_init(&tcg_region_hybrid.lock);
    tcg_region_hybrid.tb_size = tb_size;
    tcg_region_hybrid.splitwx = splitwx;
    tcg_region_hybrid.max_threads = max_threads;
    tcg_region_hybrid.buf[tcg_tcti_active()] = (TCGHybridBuffer) {
        .cb = *cb,
        .prot = prot,
    };
}

static void tcg_code_buffer_unmap(const TCGCodeBuffer *cb)
{
    munmap(cb->start, cb->size);
    if (cb->splitwx_diff) {
        munmap(cb->start + cb->splitwx_diff, cb->size);
    }
}

void tcg_region_hybrid_lock(void)
{
    qemu_mutex_lock(&tcg_region_hybrid.lock);
}

void tcg_region_hybrid_unlock(void)
{
    qemu_mutex_unlock(&tcg_region_hybrid.lock);
}

#if TCTISH_BLESSING_POSSIBLE
/*
 * Has the debugger prepare a released native buffer again, as far as it was
 * prepared when first mapped: everything after the first page, which held the
 * prologue and was never emptied, up to the first chunk.
 */
static bool tcg_region_hybrid_reprepare(TCGHybridBuffer *b, Error **errp)
{
    size_t page = qemu_real_host_page_size();
    size_t total = b->laid_out ? b->total_size : b->cb.size;
    size_t chunk = tctish_requested_chunk();
    size_t first = (chunk != 0 && chunk < total) ? chunk : total;
    char *from = (char *)b->cb.start + b->cb.splitwx_diff + page;
    void *prepared;

    /* A piece that could not be kept may be purged from under it. */
    if (b->ever_unprotected) {
        error_setg(errp, "native code's buffer cannot be prepared again");
        return false;
    }

    /* Trapping with nothing listening kills the process. */
    if (!is_debugger_attached()) {
        error_setg(errp, "no debugger is attached to prepare native code");
        return false;
    }

    prepared = jit26_prepare_region(from, first - page);
    jit26_detach();
    if (prepared != from) {
        error_setg(errp, "debugger prepared %p, not the jit region %p",
                   prepared, from);
        return false;
    }

    b->cb.usable_bytes = first;
    b->released = false;
    return true;
}
#endif

/*
 * Maps the code buffer for TCTI (tcti) or for native code, unless it is mapped
 * already, or prepares it again if it was released. Returns 1 if this mapped
 * or prepared it, 2 if there was nothing to do, or 0, with errp set, if it
 * could not; then nothing has changed.
 *
 * With tcg_region_hybrid_lock() held, from any thread, while the guest runs in
 * the buffer in use. Under TXM the native backend's buffer is prepared here,
 * or its first chunk, as at startup: the debugger must be attached already,
 * and everything stops while it works.
 */
int tcg_region_hybrid_prepare__locked(bool tcti, Error **errp)
{
    TCGHybridBuffer *b = &tcg_region_hybrid.buf[tcti];
    TCGCodeBuffer cb;
    int prot;

    if (b->cb.start != NULL) {
#if TCTISH_BLESSING_POSSIBLE
        if (b->released) {
            return tcg_region_hybrid_reprepare(b, errp) ? 1 : 0;
        }
#endif
        return 2;
    }

    prot = alloc_code_gen_buffer(tcg_region_hybrid.tb_size,
                                 tcti ? 0 : tcg_region_hybrid.splitwx, tcti,
                                 &cb, errp);
    if (prot < 0) {
        return 0;
    }

    /*
     * At startup a buffer no debugger prepared is left to fail where it is
     * executed; here the guest is running in the other one, and stays there.
     */
    if (cb.unprepared) {
        tcg_code_buffer_unmap(&cb);
        error_setg(errp, "no debugger was attached to prepare native code");
        return 0;
    }

    b->cb = cb;
    b->prot = prot;
    return 1;
}

int tcg_region_hybrid_prepare(bool tcti, Error **errp)
{
    int ret;

    tcg_region_hybrid_lock();
    ret = tcg_region_hybrid_prepare__locked(tcti, errp);
    tcg_region_hybrid_unlock();
    return ret;
}

/* Whether the native backend's buffer is mapped and prepared, ready to use. */
bool tcg_region_hybrid_native_ready(void)
{
    TCGHybridBuffer *b = &tcg_region_hybrid.buf[0];
    bool ready;

    tcg_region_hybrid_lock();
    ready = b->cb.start != NULL && !b->released;
    tcg_region_hybrid_unlock();
    return ready;
}

/*
 * Gives the native backend's buffer back to the system while TCTI is in use,
 * so that the guest's native code costs nothing while it is not running, and
 * returns whether it was given back (or there was nothing to give); if not,
 * errp says why. A refusal changes nothing; under TXM a failure part way
 * leaves the buffer to be prepared again, as if it had all been given back.
 *
 * What it costs is the way back: the next switch to native code maps and
 * prepares its buffer again, which under TXM needs the debugger, where coming
 * back to a parked buffer does not. In tctiSH, the user's to choose.
 *
 *  - Under TXM, the buffer is emptied, piece by purgeable piece, as a release
 *    of everything empties it (tctish_purgeable), and stays mapped: its
 *    addresses keep their executability, and what was prepared is prepared
 *    again from the same place. Its first page, with the prologue, stays.
 *    One that could not be made purgeable is refused: releasing it would
 *    cost its executability for good.
 *  - Anywhere else, it is unmapped, and mapped afresh for the next switch.
 */
bool tcg_region_hybrid_release_native(Error **errp)
{
    TCGHybridBuffer *b = &tcg_region_hybrid.buf[0];
    bool ok = true;

    tcg_region_hybrid_lock();

    if (!tcg_tcti_active()) {
        error_setg(errp, "native code is in use");
        ok = false;
        goto out;
    }
    if (b->cb.start == NULL || b->released) {
        goto out;
    }

#if TCTISH_BLESSING_POSSIBLE
    if (jit_region_blessing_wanted()) {
        size_t page = qemu_real_host_page_size();
        char *rw = b->cb.start;
        size_t start, end;

        if (!b->cb.purgeable || b->ever_unprotected) {
            error_setg(errp, "native code's buffer cannot be released and "
                       "prepared again");
            ok = false;
            goto out;
        }

        /*
         * Made non-volatile again at once, as in a release: the pages are gone
         * either way, and a piece the kernel could purge later could not be
         * translated into once prepared again.
         */
        for (size_t offset = page; offset < b->cb.size; offset = end) {
            int state = VM_PURGABLE_EMPTY;

            tctish_piece_at(offset, b->cb.size, &start, &end);
            if (mach_vm_purgable_control(mach_task_self(),
                                         (mach_vm_address_t)(rw + start),
                                         VM_PURGABLE_SET_STATE,
                                         &state) != KERN_SUCCESS) {
                /* Nothing changed there; what was emptied is prepared again. */
                error_setg(errp, "could not empty native code's buffer at "
                           "%zu MiB", (size_t)(start / MiB));
                ok = false;
                break;
            }
            state = VM_PURGABLE_NONVOLATILE;
            if (mach_vm_purgable_control(mach_task_self(),
                                         (mach_vm_address_t)(rw + start),
                                         VM_PURGABLE_SET_STATE,
                                         &state) != KERN_SUCCESS) {
                error_setg(errp, "could not keep native code's buffer at "
                           "%zu MiB; it cannot be prepared again",
                           (size_t)(start / MiB));
                b->ever_unprotected = true;
                ok = false;
                break;
            }
        }

        b->cb.usable_bytes = page;
        b->released = true;
        goto out;
    }
#endif

    tcg_code_buffer_unmap(&b->cb);
    if (b->laid_out) {
        for (size_t i = 0; i < b->n; i++) {
            struct tcg_region_tree *rt = b->trees + i * tree_size;

            q_tree_destroy(rt->tree);
            qemu_mutex_destroy(&rt->lock);
        }
        qemu_vfree(b->trees);
    }
    *b = (TCGHybridBuffer) { };

out:
    tcg_region_hybrid_unlock();
    return ok;
}

/* Puts the buffer in use, as it is now, in its description. */
static void tcg_region_hybrid_park(TCGHybridBuffer *b)
{
    b->cb.usable_bytes = tctish_usable_bytes;
    b->cb.chunked = tctish_chunked;
    b->cb.purgeable = tctish_purgeable;
    b->ever_unprotected = tctish_ever_unprotected;

    b->n = region.n;
    b->size = region.size;
    b->stride = region.stride;
    b->total_size = region.total_size;
    b->min_available = region.min_available;
    b->trees = region_trees;
    b->laid_out = true;
}

/* Makes a parked or newly mapped buffer the one in use. */
static void tcg_region_hybrid_unpark(TCGHybridBuffer *b)
{
    tcg_region_take_buffer(&b->cb);
    tctish_ever_unprotected = b->ever_unprotected;

    if (!b->laid_out) {
        tcg_region_layout(tcg_region_hybrid.tb_size,
                          tcg_region_hybrid.max_threads, b->prot);
        tcg_region_trees_init();
        return;
    }

    region.n = b->n;
    region.size = b->size;
    region.stride = b->stride;
    region.total_size = b->total_size;
    region.min_available = b->min_available;
    region.after_prologue = region.start_aligned;
    region_trees = b->trees;

    /*
     * As far as it is prepared, which a grow, a shrink or a release while it
     * was parked has moved. The same count tcg_region_set_usable() keeps.
     */
    region.available = MAX(tcg_regions_within(tctish_usable_bytes),
                           region.min_available);
}

/*
 * Makes the newly active backend's buffer the code buffer, and gives the
 * initial context its first region for the prologue.
 *
 * Call from safe work, with tcg_region_hybrid_lock() held since the buffer
 * was prepared (tcg_region_hybrid_prepare__locked()), every TB flushed, and
 * tcg_hybrid_tcti already set to the backend being switched to. Its regions
 * are handed to the vCPUs' contexts by tcg_region_reset_all() once the
 * prologue is in.
 */
void tcg_region_hybrid_switch(void)
{
    TCGHybridBuffer *to = &tcg_region_hybrid.buf[tcg_tcti_active()];
    TCGHybridBuffer *from = &tcg_region_hybrid.buf[!tcg_tcti_active()];

    g_assert(to->cb.start != NULL && !to->released);

    /*
     * The code cache's state goes with its buffer: a grow or a shrink from
     * the app's thread is for one or the other, never half of each.
     */
    qemu_mutex_lock(&tctish_cache_lock);

    /*
     * A shrink asked for since the flush is the leaving buffer's to pay, and
     * nothing has run since the flush to make it unsafe.
     */
    tctish_release_unused__locked();
    tcg_region_hybrid_park(from);

    /*
     * Leaving TCTI, its buffer's contents are dead -- every TB was just
     * flushed -- so its pages go back to the system until it is used again.
     * The native backend's stay: keeping it as prepared is the point of
     * parking it, and under TXM what was executable and is released must be
     * prepared again.
     */
    if (!tcg_tcti_active()) {
        /* Region by region, while `region` still describes it. */
#ifdef MADV_FREE_REUSABLE
        int err = tctish_madvise_regions(0, region.total_size,
                                         MADV_FREE_REUSABLE);

        if (err != 0) {
            warn_report("code cache: could not release TCTI's buffer: %s",
                        strerror(err));
        }
#else
        qemu_madvise(from->cb.start, from->cb.size, QEMU_MADV_DONTNEED);
#endif
    }

    tcg_region_hybrid_unpark(to);

#ifdef MADV_FREE_REUSE
    /* Back in use, after the release when it was left; for the accounting. */
    if (tcg_tcti_active() && to->laid_out) {
        tctish_madvise_regions(0, region.total_size, MADV_FREE_REUSE);
    }
#endif

    qemu_mutex_unlock(&tctish_cache_lock);

    qemu_mutex_lock(&region.lock);
    region.current = 0;
    region.agg_size_full = 0;
    tcg_region_initial_alloc__locked(&tcg_init_ctx);
    qemu_mutex_unlock(&region.lock);
}
#endif

/*
 * Initializes region partitioning.
 *
 * Called at init time from the parent thread (i.e. the one calling
 * tcg_context_init), after the target's TCG globals have been set.
 *
 * Region partitioning works by splitting code_gen_buffer into separate regions,
 * and then assigning regions to TCG threads so that the threads can translate
 * code in parallel without synchronization.
 *
 * In system-mode the number of TCG threads is bounded by max_threads,
 *
 * In user-mode we use a single region.  Having multiple regions in user-mode
 * is not supported, because the number of vCPU threads (recall that each thread
 * spawned by the guest corresponds to a vCPU thread) is only bounded by the
 * OS, and usually this number is huge (tens of thousands is not uncommon).
 * Thus, given this large bound on the number of vCPU threads and the fact
 * that code_gen_buffer is allocated at compile-time, we cannot guarantee
 * that the availability of at least one region per vCPU thread.
 *
 * However, this user-mode limitation is unlikely to be a significant problem
 * in practice. Multi-threaded guests share most if not all of their translated
 * code, which makes parallel code generation less appealing than in system-mode
 */
void tcg_region_init(size_t tb_size, int splitwx, unsigned max_threads)
{
    const size_t page_size = qemu_real_host_page_size();
    TCGCodeBuffer cb = { };
    int have_prot;

    /* Size the buffer.  */
    if (tb_size == 0) {
        size_t phys_mem = qemu_get_host_physmem();
        if (phys_mem == 0) {
            tb_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
        } else {
            tb_size = QEMU_ALIGN_DOWN(phys_mem / 8, page_size);
            tb_size = MIN(DEFAULT_CODE_GEN_BUFFER_SIZE, tb_size);
        }
    }
    if (tb_size < MIN_CODE_GEN_BUFFER_SIZE) {
        tb_size = MIN_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size > MAX_CODE_GEN_BUFFER_SIZE) {
        tb_size = MAX_CODE_GEN_BUFFER_SIZE;
    }

#ifdef CONFIG_TCG_HYBRID_RUNTIME
    /* TCTI's buffer holds data; split-wx is for the native backend's. */
    have_prot = alloc_code_gen_buffer(tb_size, tcg_tcti_active() ? 0 : splitwx,
                                      tcg_tcti_active(), &cb, &error_fatal);
    assert(have_prot >= 0);
    tcg_region_hybrid_init(tb_size, splitwx, max_threads, &cb, have_prot);
#else
    have_prot = alloc_code_gen_buffer(tb_size, splitwx, tcg_tcti_active(), &cb,
                                      &error_fatal);
    assert(have_prot >= 0);
#endif
    tcg_region_take_buffer(&cb);

    tcg_region_layout(tb_size, max_threads, have_prot);

    /* init the region struct */
    qemu_mutex_init(&region.lock);

    /*
     * Before the ready flag below, because that is what lets the app call in
     * from its own thread -- and every one of those calls takes this.
     */
    qemu_mutex_init(&tctish_cache_lock);

    tcg_region_trees_init();

    /*
     * Leave the initial context initialized to the first region.
     * This will be the context into which we generate the prologue.
     * It is also the only context for CONFIG_USER_ONLY.
     */
    tcg_region_initial_alloc__locked(&tcg_init_ctx);

    /* Last, and with a barrier: see tcg_region_ready(). */
    qatomic_store_release(&region.ready, true);
}

void tcg_region_prologue_set(TCGContext *s)
{
    /* Deduct the prologue from the first region.  */
    g_assert(region.start_aligned == s->code_gen_buffer);
    region.after_prologue = s->code_ptr;

    /* Recompute boundaries of the first region. */
    tcg_region_assign(s, 0);

    /* Register the balance of the buffer with gdb. */
    tcg_register_jit(tcg_splitwx_to_rx(region.after_prologue),
                     region.start_aligned + region.total_size -
                     region.after_prologue);
}

/*
 * Returns the size (in bytes) of all translated code (i.e. from all regions)
 * currently in the cache.
 * See also: tcg_code_capacity()
 * Do not confuse with tcg_current_code_size(); that one applies to a single
 * TCG context.
 */
size_t tcg_code_size(void)
{
    unsigned int n_ctxs = qatomic_read(&tcg_cur_ctxs);
    unsigned int i;
    size_t total;

    qemu_mutex_lock(&region.lock);
    total = region.agg_size_full;
    for (i = 0; i < n_ctxs; i++) {
        const TCGContext *s = qatomic_read(&tcg_ctxs[i]);
        size_t size;

        size = qatomic_read(&s->code_gen_ptr) - s->code_gen_buffer;
        g_assert(size <= s->code_gen_buffer_size);
        total += size;
    }
    qemu_mutex_unlock(&region.lock);
    return total;
}

/*
 * Returns the code capacity (in bytes) of the entire cache, i.e. including all
 * regions.
 * See also: tcg_code_size()
 */
size_t tcg_code_capacity(void)
{
    size_t guard_size, capacity;

    /* no need for synchronization; these variables are set at init time */
    guard_size = region.stride - region.size;
    capacity = region.total_size;
    capacity -= (region.n - 1) * guard_size;
    capacity -= region.n * TCG_HIGHWATER;

    return capacity;
}

/*
 * Whether the regions exist yet.
 *
 * The buffer is allocated before it is partitioned, so there is a window in
 * which the code cache has a size and can be asked about -- tctiSH does exactly
 * that, from its own thread, as soon as the size is non-zero -- while
 * region.lock is still uninitialised memory and every field beside it is zero.
 *
 * Its own flag rather than a non-zero `region.n`, because `region.n` is written
 * first and is read during the rest of the setup; only something written last
 * can stand for "all of this is safe to read".
 */
static bool tcg_region_ready(void)
{
    return qatomic_load_acquire(&region.ready);
}

static size_t tcg_region_usable_size(void)
{
    size_t n;

    if (!tcg_region_ready()) {
        return 0;
    }

    qemu_mutex_lock(&region.lock);
    n = region.available;
    qemu_mutex_unlock(&region.lock);

    return n * (region.size - TCG_HIGHWATER);
}

static void tcg_region_set_usable(size_t bytes)
{
    size_t n;

    if (!tcg_region_ready()) {
        return;
    }

    n = MAX(tcg_regions_within(bytes), region.min_available);

    qemu_mutex_lock(&region.lock);
    region.available = n;
    qemu_mutex_unlock(&region.lock);
}

static size_t tcg_region_usable_end(void)
{
    void *start, *end;
    size_t n;

    if (!tcg_region_ready()) {
        return 0;
    }

    qemu_mutex_lock(&region.lock);
    n = region.available;
    qemu_mutex_unlock(&region.lock);

    if (n == 0) {
        return 0;
    }

    /*
     * Asked of the region rather than worked out as n * .stride.
     *
     * The last region is the one that matters: tcg_region_init() hands it
     * whatever pages are left over once the buffer has been divided, so as soon
     * as every region is available n * .stride falls *short* of where TCG may
     * really translate -- and a caller that believed it would unprotect and
     * discard pages inside a region still being handed out. That failure
     * arrives as an illegal instruction fetch in generated code.
     */
    tcg_region_bounds(n - 1, &start, &end);

    /*
     * Past the guard page, which belongs to the region and is not ours to give
     * -- but never past the buffer. The final region is handed whatever pages
     * were left over by the division and ends at total_size, which already
     * excludes the last guard page, so adding one there would name a byte that
     * does not exist.
     */
    return MIN((size_t)((char *)end + qemu_real_host_page_size()
                        - (char *)region.start_aligned),
               region.total_size);
}

/* How much of the code buffer exists at all, in bytes. */
size_t tctish_code_cache_total(void)
{
    return tcg_region_ready() ? region.total_size : 0;
}

/*
 * How much the last release actually handed back, or 0 if it could not.
 *
 * Reported rather than merely logged: `error_report` goes to stderr, and nothing
 * captures QEMU's stderr outside a debugger session -- so on the devices where
 * this matters most, a failure would be silent.
 */
static size_t tctish_released_bytes;

/* How many times a release has been attempted, and what went wrong last. */
static size_t tctish_release_attempts;

/*
 * Kept apart for the two halves of the split mapping.
 *
 * They are not the same question. The writable alias is ordinary private
 * anonymous memory; the executable one is an alias of it made by
 * mach_vm_remap(), is read-execute, and is shared with the first. If only the
 * second refuses, the shape of the mapping is the problem and there is
 * something to be done about it; if both do, remapped memory simply cannot be
 * handed back and the whole idea has to go.
 */
static int tctish_release_errno_rw;
static int tctish_release_errno_rx;

size_t tctish_code_cache_released(void)
{
    return tctish_released_bytes;
}

size_t tctish_code_cache_release_attempts(void)
{
    return qatomic_load_acquire(&tctish_release_attempts);
}

/*
 * Counts an attempt, once its outcome is recorded. Last, and with release
 * ordering, because the app watches the count and reads the outcome the moment
 * it moves. Measured on device: counted first, a 512 MiB release was still
 * under way when the app looked, and read back as having given nothing.
 */
static void tctish_release_attempted(void)
{
    qatomic_store_release(&tctish_release_attempts,
                          tctish_release_attempts + 1);
}

int tctish_code_cache_release_errno(void)
{
    return tctish_release_errno_rw;
}

int tctish_code_cache_release_errno_rx(void)
{
    return tctish_release_errno_rx;
}

#ifdef CONFIG_DARWIN
/*
 * How much of [start, start + length) the kernel holds a copy of, resident or
 * compressed. Whole pages; `start` and `length` are page-aligned by the caller.
 */
static size_t tctish_resident_bytes(char *start, size_t length)
{
    size_t page = qemu_real_host_page_size();
    size_t total = 0;
    char vec[256];

    for (size_t done = 0; done < length;) {
        size_t chunk = MIN(length - done, sizeof(vec) * page);
        size_t pages = chunk / page;

        if (mincore(start + done, chunk, vec) != 0) {
            return 0;
        }
        for (size_t i = 0; i < pages; i++) {
            if (vec[i] & (MINCORE_INCORE | MINCORE_PAGED_OUT)) {
                total += page;
            }
        }
        done += chunk;
    }

    return total;
}
#endif

/*
 * Hands the unused tail of the code buffer back to the system.
 *
 * `MADV_FREE_REUSABLE` is the Darwin call that actually moves the needle. Plain
 * `MADV_FREE` leaves the pages counted against the process until something
 * reclaims them, which is no use to an app trying not to be killed for its
 * footprint; REUSABLE drops them from it there and then.
 *
 * Both halves of the split mapping get it. They are two views of the same pages,
 * and a page still mapped for execution somewhere is not a page the system can
 * take back.
 *
 * Call with tctish_cache_lock held.
 */
static void tctish_pay_release__locked(void)
{
#ifdef CONFIG_DARWIN
    size_t total = region.total_size;
    size_t keep = tctish_usable_bytes;
    char *rw = (char *)region.start_aligned;
    size_t length;
    bool everything = false;

    /* Only what a shrink gave up; see tctish_release_pending. */
    if (!tctish_release_pending) {
        return;
    }
    tctish_release_pending = false;

    /* Everything after the prologue; see tctish_code_cache_release_all(). */
    if (tctish_release_everything) {
        tctish_release_everything = false;
        everything = true;
        keep = (char *)region.after_prologue - rw;
    }

    /*
     * Cleared here rather than only on the paths that go on to try, so that the
     * figure always describes the shrink being paid out now. Left standing, the
     * previous success would be read back as this one's.
     */
    tctish_released_bytes = 0;

    /*
     * Zero is only a boundary nobody has set, except when everything is going:
     * under TCTI there is no prologue, so everything starts at the very front.
     */
    if ((keep == 0 && !everything) || keep >= total || rw == NULL) {
        return;
    }

    if (tctish_release_upto > total) {
        tctish_release_upto = total;
    }
    if (tctish_release_upto <= keep) {
        return;
    }

    length = tctish_release_upto - keep;

    /* Whole pages only, and never a page that is partly still in use. */
    {
        char *from = rw + keep;

        if (!tctish_pages_within(&from, &length)) {
            return;
        }
        keep = from - rw;
    }

    /*
     * After a release of everything, nothing past the prologue's page may be
     * assumed prepared, whatever the kernel makes of the advice below: the
     * protection changes first. So the next grow prepares from here. (After an
     * ordinary shrink the boundary is already where the shrink put it.)
     */
    if (everything) {
        tctish_usable_bytes = keep;
        qatomic_set(&tctish_needs_preparing, true);
    }

#ifdef MADV_FREE_REUSABLE
    bool released = true;
    size_t resident;

    /*
     * Counted separately from the bytes, because "gave nothing back" and "was
     * never asked" are the same number and only one of them is a problem. See
     * tctish_release_attempted() for why the count comes at the end.
     */
    tctish_release_errno_rw = 0;
    tctish_release_errno_rx = 0;

#if TCTISH_BLESSING_POSSIBLE
    /*
     * Emptied instead, where the buffer allows it: see tctish_purgeable. Every
     * piece lying wholly within the range goes, which for a release of
     * everything is all of them; a piece the range only reaches into is kept,
     * whole, still prepared and still executable.
     *
     * Each is made non-volatile again at once. The pages are gone either way;
     * what matters is that the kernel cannot purge a piece on its own later,
     * from under code TCG has translated into it since.
     */
    if (tctish_purgeable) {
        size_t size = region.total_size;
        size_t emptied = 0;
        size_t start, end;

        for (size_t offset = keep; offset < keep + length; offset = end) {
            int state = VM_PURGABLE_EMPTY;
            size_t in_core;
            kern_return_t ret;

            tctish_piece_at(offset, size, &start, &end);
            if (start < keep || end > keep + length) {
                continue;
            }

            in_core = tctish_resident_bytes(rw + start, end - start);
            ret = mach_vm_purgable_control(mach_task_self(),
                                           (mach_vm_address_t)(rw + start),
                                           VM_PURGABLE_SET_STATE, &state);
            if (ret != KERN_SUCCESS) {
                /* Nothing changed there, so nothing is lost. */
                error_report("code cache: could not empty the piece at %zu "
                             "MiB: %d", (size_t)(start / MiB), ret);
                tctish_release_errno_rw = EPERM;
                break;
            }
            emptied += in_core;

            state = VM_PURGABLE_NONVOLATILE;
            ret = mach_vm_purgable_control(mach_task_self(),
                                           (mach_vm_address_t)(rw + start),
                                           VM_PURGABLE_SET_STATE, &state);
            if (ret != KERN_SUCCESS) {
                /*
                 * Volatile memory can be taken at any moment, so none of it
                 * may be translated into. Refusing to grow is what ensures
                 * that, and the app, failing to prepare, asks what to do.
                 */
                error_report("code cache: could not keep the piece at %zu "
                             "MiB: %d; growth stops here", (size_t)(start / MiB), ret);
                tctish_ever_unprotected = true;
                break;
            }
        }

        tctish_released_bytes = emptied;
        tctish_release_attempted();
        return;
    }
#endif

    /* What was resident, which is what comes off the footprint; not the range. */
    resident = tctish_resident_bytes(rw + keep, length);

    /*
     * The executable alias first, and only after making it writable.
     *
     * Measured on device: the writable mapping accepts MADV_FREE_REUSABLE and
     * the executable one answers EPERM. The kernel will not discard pages
     * through a read-execute view of them, and while it holds on to them
     * through that view the writable side's consent counts for nothing.
     *
     * Under TXM this is one-way: those addresses can never be executed again
     * in this process; see tctish_ever_unprotected. Growth stops here, and a
     * release of everything is refused outright. Only reached under TXM when
     * the buffer couldn't be made purgeable.
     */
    if (tcg_splitwx_diff != 0) {
        char *rx = rw + tcg_splitwx_diff;

        if (mprotect(rx + keep, length, PROT_READ | PROT_WRITE) != 0) {
            /*
             * Taken before anything else runs. error_report() goes through
             * glib and stdio, either of which may leave errno as it pleases --
             * and this number is the whole point of keeping the two halves
             * apart, so reading it back second-hand would defeat the exercise.
             */
            tctish_release_errno_rx = errno;
            error_report("code cache: could not unprotect %zu bytes (rx): %s",
                         length, strerror(tctish_release_errno_rx));
            released = false;
        } else {
            /*
             * Recorded the moment the protection changes, and not below with
             * the outcome: from here on the restore in tctish_code_cache_grow()
             * has work to do whether or not the kernel takes the pages.
             */
            tctish_ever_unprotected = true;

            if (madvise(rx + keep, length, MADV_FREE_REUSABLE) != 0) {
                /* Before reporting; see above. */
                tctish_release_errno_rx = errno;
                error_report("code cache: could not release %zu bytes (rx): %s",
                             length, strerror(tctish_release_errno_rx));
                released = false;
            }
        }
    }

    /* Around the guard pages; see tctish_madvise_regions(). */
    tctish_release_errno_rw = tctish_madvise_regions(keep, keep + length,
                                                     MADV_FREE_REUSABLE);
    if (tctish_release_errno_rw != 0) {
        /* Not fatal: the pages stay ours, and the cap on growth still holds. */
        error_report("code cache: could not release %zu bytes (rw): %s",
                     length, strerror(tctish_release_errno_rw));
        released = false;
    }

    /* What was resident, which is what comes off the footprint; not the range. */
    tctish_released_bytes = released ? resident : 0;
    tctish_release_attempted();
#endif
#endif
}

/*
 * Pays out whatever release is pending, and marks a release of everything
 * settled either way, so that nobody waits on one that came to nothing. Call
 * with tctish_cache_lock held.
 */
static void tctish_release_unused__locked(void)
{
    bool everything = tctish_release_pending && tctish_release_everything;

    tctish_pay_release__locked();

    if (everything) {
        qatomic_store_release(&tctish_release_all_outstanding, false);
    }
}

void tctish_release_unused(void)
{
    if (!tcg_region_ready()) {
        return;
    }

    qemu_mutex_lock(&tctish_cache_lock);
    tctish_release_unused__locked();
    qemu_mutex_unlock(&tctish_cache_lock);
}

/* How much of it may be translated into right now, in bytes. */
size_t tctish_code_cache_usable(void)
{
    return tcg_region_usable_size();
}

/* How much translated code is in it, in bytes. */
size_t tctish_code_cache_used(void)
{
    return tcg_code_size();
}

/*
 * Whether growing the cache needs a debugger attached first.
 *
 * True only where pages must be prepared before they will execute. Under TCTI
 * nothing is ever executed directly, so nothing needs preparing and growing is
 * just arithmetic -- no helper, no trap, and no freeze.
 */
bool tctish_code_cache_needs_debugger(void)
{
#if TCTISH_BLESSING_POSSIBLE
    return jit_region_blessing_requested();
#else
    return false;
#endif
}

/* Whether there is anything left to bring into use. */
bool tctish_code_cache_can_grow(void)
{
#if TCTISH_BLESSING_POSSIBLE
    if (jit_region_blessing_requested() && tctish_ever_unprotected) {
        return false;
    }
#endif
    return tcg_region_ready() && tctish_usable_bytes < region.total_size;
}

/*
 * Reduces the usable part of the code buffer to `target` bytes, and returns what
 * is usable afterwards -- or 0 if nothing changed.
 *
 * Two halves, deliberately. The cap comes down immediately, which costs nothing
 * and stops the cache being grown any further. The memory itself comes back at
 * the next flush, because that is the only moment the tail is provably empty --
 * so a flush is asked for rather than waited for.
 *
 * Anything released has to be prepared again before it can be executed: the
 * pages the system takes back are not the pages that come back, and whatever
 * made the old ones executable did not survive them. Lowering
 * `tctish_usable_bytes` is what makes the next grow re-prepare rather than
 * assume.
 */
size_t tctish_code_cache_shrink(size_t target)
{
    size_t previous;

    /*
     * Nothing to move until the buffer has been partitioned; see
     * tcg_region_usable_size(), which answers zero until then and cannot answer
     * zero afterwards. Without this the boundary would be set from a region
     * layout that does not exist yet, and land on zero.
     */
    if (tcg_region_usable_size() == 0) {
        return 0;
    }

    qemu_mutex_lock(&tctish_cache_lock);
    previous = tctish_usable_bytes;

    if (target >= previous) {
        qemu_mutex_unlock(&tctish_cache_lock);
        return 0;
    }

    tcg_region_set_usable(target);

    /* What the regions actually came to, which is where the release will cut. */
    tctish_usable_bytes = tcg_region_usable_end();

    /*
     * The highest boundary any unpaid shrink started from, so that two of them
     * before a single flush still give back everything between them.
     */
    if (!tctish_release_pending || previous > tctish_release_upto) {
        tctish_release_upto = previous;
    }
    tctish_release_pending = true;
    qemu_mutex_unlock(&tctish_cache_lock);

    /*
     * Outside the lock. The flush it asks for ends in a release, which takes
     * the same lock, and there is nothing to be gained by making that wait on
     * this.
     */
    tctish_request_flush();

    return tcg_region_usable_size();
}

/*
 * Hands the whole code buffer back to the system at the next flush, all but
 * the page holding the prologue, and returns whether a release was arranged.
 *
 * A shrink can only go as low as a region per vCPU, and after a flush those
 * first regions are exactly where TCG translates into again, so a shrink gives
 * back the tail and keeps nearly everything that was ever resident. This takes
 * the kept regions too.
 *
 * Only for a machine that cannot run until the app has put the usable size
 * back with tctish_code_cache_grow(): in tctiSH, a parked one.
 *
 * Refused wherever the buffer has an executable alias and is not purgeable.
 * Releasing through that alias costs its addresses their executability for
 * good under TXM (see tctish_ever_unprotected), and before TXM nothing puts it
 * back. A purgeable buffer is emptied instead, which touches neither alias;
 * see tctish_purgeable. So: TCTI, where nothing is executed from the buffer at
 * all, and JIT under TXM when the buffer could be made purgeable.
 *
 * The flush is asked for here, and runs on the vCPUs even while the machine
 * is stopped; watch tctish_code_cache_release_attempts() to see it happen.
 */
bool tctish_code_cache_release_all(void)
{
    if (tcg_region_usable_size() == 0 ||
        (tcg_splitwx_diff != 0 && !tctish_purgeable)) {
        return false;
    }

    qemu_mutex_lock(&tctish_cache_lock);
    tctish_release_everything = true;
    tctish_release_upto = region.total_size;
    tctish_release_pending = true;
    qatomic_store_release(&tctish_release_all_outstanding, true);
    qemu_mutex_unlock(&tctish_cache_lock);

    tctish_request_flush();
    return true;
}

/* Whether a release of everything is still waiting for its flush. */
bool tctish_code_cache_release_all_outstanding(void)
{
    return qatomic_load_acquire(&tctish_release_all_outstanding);
}

/* Whether a release of everything has left the cache to be prepared again. */
bool tctish_code_cache_needs_preparing(void)
{
    return qatomic_read(&tctish_needs_preparing);
}

/* Whether the machine may run, as far as the code cache goes. */
bool tctish_code_cache_may_run(void)
{
    return !tctish_code_cache_release_all_outstanding() &&
           !tctish_code_cache_needs_preparing();
}

/*
 * Brings the code buffer into use up to `target` bytes, and returns how much is
 * usable afterwards -- or zero if nothing changed.
 *
 * The caller chooses the target rather than this stepping by some size of its
 * own, because the ladder is a policy question: how far the user let it go, how
 * big a freeze they will sit through. All this enforces is the buffer's own
 * limit.
 *
 * The caller must have a debugger attached before calling this, because that is
 * what makes the new pages executable, and this cannot arrange one: the trap
 * below stops every thread in the process, so the thread that would have gone
 * looking for a helper is stopped along with the rest. In tctiSH the app
 * attaches one and then calls in.
 *
 * No vCPU needs stopping, and no flush is needed. The pages being prepared are
 * ones no context can reach -- tcg_region_alloc__locked() will not hand them out
 * until the count is raised, which is the last thing done here -- so everything
 * already translated stays exactly where it is.
 *
 * A release waiting to be paid does have to be seen off first, though, which is
 * what the lock is for: see tctish_cache_lock.
 */
size_t tctish_code_cache_grow(size_t target)
{
    size_t total;
    size_t usable;

    /* As in the shrink: there is no point preparing regions that do not exist. */
    if (tcg_region_usable_size() == 0) {
        return 0;
    }

    total = region.total_size;

    qemu_mutex_lock(&tctish_cache_lock);

    if (tctish_usable_bytes >= total) {
        goto unchanged;
    }

    if (target > total) {
        target = total;
    }
    if (target <= tctish_usable_bytes) {
        goto unchanged;
    }

#if TCTISH_BLESSING_POSSIBLE
    if (jit_region_blessing_requested()) {
        void *rx = (void *)((uintptr_t)region.start_aligned + tcg_splitwx_diff);
        void *from = (char *)rx + tctish_usable_bytes;
        size_t len = target - tctish_usable_bytes;
        void *prepared;

        /* Released pages cannot be made executable again; see the flag. */
        if (tctish_ever_unprotected) {
            error_report("code cache: cannot grow past a release under TXM");
            goto unchanged;
        }

        /* Trapping with nothing listening kills the process. */
        if (!is_debugger_attached()) {
            goto unchanged;
        }

        /*
         * `from` is not page-aligned, and deliberately need not be.
         *
         * A script stepping a page at a time from an unaligned start covers one
         * page fewer than the range spans -- but the page it misses at each end
         * is a region's guard page, never a page TCG hands out: regions end one
         * page short (tcg_region_bounds()), and both `tctish_usable_bytes` and
         * `target` land on region boundaries or beyond them.
         *
         * Aligning `from` outward instead would be the real mistake, since that
         * is the direction that lets a usable page go unprepared.
         */
        prepared = jit26_prepare_region(from, len);
        jit26_detach();

        if (prepared != from) {
            goto unchanged;
        }
    }
#endif

    tctish_usable_bytes = target;
    tcg_region_set_usable(target);
    usable = tcg_region_usable_size();
    qatomic_set(&tctish_needs_preparing, false);
    qemu_mutex_unlock(&tctish_cache_lock);
    return usable;

unchanged:
    qemu_mutex_unlock(&tctish_cache_lock);
    return 0;
}
