if not have_tcg
   subdir_done()
endif

tcg_ss = ss.source_set()

tcg_ss.add(files(
  'cpu-exec-common.c',
  'tcg-runtime.c',
  'tcg-runtime-gvec.c',
  'tb-maint.c',
  'tcg-all.c',
  'tcg-stats.c',
  'translate-all.c',
  'translator.c',
))
if get_option('plugins')
  tcg_ss.add(files('plugin-gen.c'))
endif

user_ss.add_all(tcg_ss)
system_ss.add_all(tcg_ss)

# Per target, so that the TB lookup can inline the target's state; see
# tb_cpu_state() in cpu-exec.c.
specific_ss.add(files('cpu-exec.c'))

user_ss.add(files(
  'user-exec.c',
  'user-exec-stub.c',
))

system_ss.add(files(
  'cputlb.c',
  'icount-common.c',
  'monitor.c',
  'tcg-accel-ops.c',
  'tcg-accel-ops-icount.c',
  'tcg-accel-ops-mttcg.c',
  'tcg-accel-ops-rr.c',
  'watchpoint.c',
))
