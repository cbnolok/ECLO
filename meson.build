project('UO Enhanced Client LOader', 'cpp',
  version: '1.3',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++17',
    'cpp_rtti=false',
    'b_lto=true',
    'b_lto_mode=default',
    'b_lto_threads=0',
    'default_library=static'
])

os_str = build_machine.system()
deps = []
linker_flags = []

# Get compiler and default build type
cxx = meson.get_compiler('cpp')
build_type = get_option('buildtype')
optimization = get_option('optimization')
summary('Build Type', build_type, section: 'Build Info')
summary('Optimization', optimization, section: 'Build Info')


# Add compiler arguments
# -Wpedantic, -Wextra comes by default with warning level

# hide/enable some warnings
compiler_warning_flags = [
  '-Wsign-compare',
  '-Wconversion',
  '-Woverflow',
  '-Wstack-protector',
  '-Winit-self',
  '-Wstrict-prototypes'
]

# secure compile flags
compiler_security_flags = [
  '-Wformat',
  '-Wformat-security',
  '-Wformat-overflow',
  #'--enable-default-ssp',# stack canary
  '-fstack-protector-all',
  #'--enable-default-pie', # PIE to support ASLR: address space location randomization
  '-pie'
]

valid_number = not optimization.to_lower().contains('abcdefghijklmnopqrstuvwxyz'.split())
if (valid_number and optimization.to_int() >= 2) or optimization == 's'
  compiler_security_flags += [
    '-D_FORTIFY_SOURCE=2'
  ]

  # mingw-w64, unlike GNU libc, does not provide fortified functions
  if os_str == 'windows' and cxx.get_id() == 'gcc'
    deps += cxx.find_library('ssp', required: true)
  endif
endif

if os_str == 'linux'
  linker_flags += [
    # RELRO (Relocation Read-Only) is a generic mitigation technique to harden the data sections of an ELF binary/process.
    '-z',
    'relro',  # partial
    '-z',
    'now'     # full
  ]
elif os_str == 'windows'
  linker_flags += [
    '-Wl,--dynamicbase'# ASLR (address space layout randomization)
  ]
endif

compiler_debug_flags = []
if build_type == 'debug'
  compiler_debug_flags += [
    '-ggdb'
  ]
endif

add_project_arguments(cxx.get_supported_arguments(compiler_warning_flags),  language: 'cpp')
add_project_arguments(cxx.get_supported_arguments(compiler_security_flags), language: 'cpp')
add_project_arguments(cxx.get_supported_arguments(compiler_debug_flags),    language: 'cpp')


#deps += dependency('tomlpp')
sources = []
subdir('src')

if os_str == 'windows'
  deps += cxx.find_library('ws2_32', required: true)

  os_win = import('windows')
  sources += os_win.compile_resources('res/resources.rc')
endif

executable('eclo', sources,
          link_args: linker_flags,
          win_subsystem: 'console',
          dependencies: deps)
