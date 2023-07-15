project('EC Passepartout', 'cpp',
  version: '1.2',
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


# Get compiler and default build type
cxx = meson.get_compiler('cpp')
build = get_option('buildtype')
optimization = get_option('optimization')
summary('Build Type', build, section : 'Build Info')
summary('Optimization', optimization, section : 'Build Info')

# Add compiler arguments
# -Wpedantic, -Wextra comes by default with warning level
# hide/enable some warnings
warning_flags = [
  '-Wno-unused-command-line-argument',
  '-Wsign-compare',
  '-Wconversion',
  '-Woverflow',
#  '-Wstack-protector',
  '-Winit-self',
  '-Wstrict-prototypes'
]

# secure compile flags
security_flags = [
#  '-fstack-protector-strong',
  '-Wformat',
  '-Wformat-security',
  '-Wformat-overflow',
  '-fno-strict-overflow',
  '-fno-delete-null-pointer-checks',
  '-fwrapv'
]

if get_option('optimization').to_int() >= 2
  security_flags += [
    '-D_FORTIFY_SOURCE=2'
  ]
endif

debug_flags = []
if get_option('buildtype') == 'debug'
  debug_flags += [
    '-ggdb'
  ]
endif

add_project_arguments(cxx.get_supported_arguments(warning_flags), language : 'cpp')
add_project_arguments(cxx.get_supported_arguments(security_flags), language : 'cpp')
add_project_arguments(cxx.get_supported_arguments(debug_flags), language : 'cpp')


deps = [] #dependency('tomlpp')
sources = []
subdir('src')

if(build_machine.system() == 'windows')
  deps += cxx.find_library('ws2_32', required: true)
endif

executable('ec_passepartout', sources,
           win_subsystem: 'windows',
           dependencies: deps)
