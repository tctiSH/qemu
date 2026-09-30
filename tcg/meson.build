if not have_tcg
   subdir_done()
endif

tcg_ss = ss.source_set()

tcg_ss.add(files(
  'optimize.c',
  'region.c',
  'tcg.c',
  'tcg-common.c',
  'tcg-op.c',
  'tcg-op-ldst.c',
  'tcg-op-gvec.c',
  'tcg-op-vec.c',
))

if get_option('tcg_interpreter')
  libffi = dependency('libffi', version: '>=3.0', required: true,
                      method: 'pkg-config')
  tcg_ss.add(libffi)
  tcg_ss.add(files('tci.c'))
endif

if get_option('tcg_threaded_interpreter')
  # The gadgets TCTI dispatches through are generated, a few collections of
  # them to a file so the compile parallelises. The list must match what
  # tcti-gadget-gen.py writes.
  tcti_collections = [
    'misc', 'setcond', 'brcond', 'movcond', 'mov',
    'load_unsigned', 'load_signed', 'store',
    'arithmetic', 'logical', 'bitwise', 'extension', 'byteswap',
    'qemu_ld_aligned_unsigned_le', 'qemu_ld_aligned_signed_le',
    'qemu_ld_unaligned_unsigned_le', 'qemu_ld_unaligned_signed_le',
    'qemu_ld_slowpath_unsigned_le', 'qemu_ld_slowpath_signed_le',
    'qemu_st_aligned_le', 'qemu_st_unaligned_le', 'qemu_st_slowpath_le',
    'qemu_ldst_i128',
    'simd_base', 'simd_arithmetic', 'simd_logical', 'simd_immediate',
  ]
  tcti_outputs = ['tcti_gadgets.h']
  foreach c : tcti_collections
    tcti_outputs += ['tcti_@0@_gadgets.c'.format(c), 'tcti_@0@_gadgets.h'.format(c)]
  endforeach
  tcti_gadget_gen = files(meson.project_source_root() / 'tcg' / tcg_arch / 'tcti-gadget-gen.py')
  tcti_gadgets = custom_target('tcti-gadgets',
                               output: tcti_outputs,
                               input: tcti_gadget_gen,
                               command: [python, '@INPUT@', '@OUTDIR@'])
  tcg_ss.add(declare_dependency(sources: tcti_gadgets))
endif

tcg_ss.add(when: libdw, if_true: files('debuginfo.c'))
if host_os == 'linux'
  tcg_ss.add(files('perf.c'))
endif

user_ss.add_all(tcg_ss)
system_ss.add_all(tcg_ss)
