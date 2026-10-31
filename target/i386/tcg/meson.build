i386_ss.add(when: 'CONFIG_TCG', if_true: files(
  'access.c',
  'bpt_helper.c',
  'cc_helper.c',
  'excp_helper.c',
  'fpu_helper.c',
  'int_helper.c',
  'mem_helper.c',
  'misc_helper.c',
  'mpx_helper.c',
  'seg_helper.c',
  'string_helper.c',
  'tcg-cpu.c',
  'translate.c'), if_false: files('tcg-stub.c'))

subdir('system')
subdir('user')

# Builds with RCG (see include/tcg/rcg.h) generate its gadgets and
# rcg-table.c.inc, the table rcg.c.inc picks them from. The file list must
# match GADGET_FILES in rcg-gen.py. rcg-gen.py also reads rcg-test.h, hence
# its dependency.
if get_option('tcg_threaded_interpreter') or \
   get_option('tcg_hybrid') in ['tcti', 'runtime']
  rcg_outputs = ['rcg-table.c.inc']
  foreach f : ['add', 'sub', 'and', 'or', 'xor', 'cmp', 'test', 'adc', 'sbb',
              'mov', 'other', 'shift', 'mul', 'bt', 'jcc', 'setcc', 'cmov',
              'fused', 'sse']
    rcg_outputs += 'rcg_gadgets_@0@.c'.format(f)
  endforeach
  rcg_gadgets = custom_target('rcg-gadgets',
                              output: rcg_outputs,
                              input: files('rcg-gen.py'),
                              depend_files: [tcti_memory, files(
                                meson.project_source_root() / 'tests' / 'tcg' /
                                'x86_64' / 'system' / 'rcg-test.h')],
                              command: [python, '@INPUT@', '--gadgets',
                                        '@OUTDIR@'])
  i386_ss.add(when: ['CONFIG_TCG', 'TARGET_X86_64'], if_true: rcg_gadgets)
endif
