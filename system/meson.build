system_ss.add(files(
  'vl.c',
), sdl, libpmem, libdaxctl)

system_ss.add(files(
  'arch_init.c',
  'balloon.c',
  'bootdevice.c',
  'cpus.c',
  'cpu-timers.c',
  'dirtylimit.c',
  'dma-helpers.c',
  'exit-with-parent.c',
  'globals.c',
  'ioport.c',
  'ram-block-attributes.c',
  'ram-discard-manager.c',
  'memory_mapping.c',
  'memory.c',
  'physmem.c',
  'qdev-monitor.c',
  'qtest.c',
  'rtc.c',
  'runstate-action.c',
  'runstate-hmp-cmds.c',
  'runstate.c',
  'tpm-hmp-cmds.c',
  'watchpoint.c',
))

if have_tpm
  system_ss.add(files('tpm.c'))
endif

system_ss.add(when: seccomp, if_true: files('qemu-seccomp.c'))
system_ss.add(when: 'CONFIG_DEVICE_TREE',
              if_true: [fdt, files('device_tree.c')],
              if_false: files('device_tree-stub.c'))
if host_os == 'linux'
  system_ss.add(files('async-teardown.c'))
endif

# Export symbols for shared lib build
if get_option('shared_lib')
  if host_os == 'darwin'
    configure_file(
      input: files('qemu.symbols'),
      output: 'qemu-ld64.symbols',
      capture: true,
      command: ['sed', '-ne', 's/^[[:space:]]*\\([a-zA-Z_$0-9]*\\);/_\\1/p', '@INPUT@'])
    emulator_link_args += ['-Wl,-exported_symbols_list,system/qemu-ld64.symbols']
  else
    emulator_link_args += ['-Xlinker', '--dynamic-list=' + (meson.project_source_root() / 'system/qemu.symbols')]
  endif
endif
