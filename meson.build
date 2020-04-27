project('libjcat', 'c',
  version : '0.1.3',
  license : 'LGPL-2.1+',
  meson_version : '>=0.49.2',
  default_options : ['warning_level=2', 'c_std=c99'],
)

libjcat_version = meson.project_version()
varr = libjcat_version.split('.')
libjcat_major_version = varr[0]
libjcat_minor_version = varr[1]
libjcat_micro_version = varr[2]

conf = configuration_data()
conf.set('JCAT_MAJOR_VERSION', libjcat_major_version)
conf.set('JCAT_MINOR_VERSION', libjcat_minor_version)
conf.set('JCAT_MICRO_VERSION', libjcat_micro_version)
conf.set_quoted('PACKAGE_VERSION', libjcat_version)

# libtool versioning - this applies to libjcat
lt_current = '1'
lt_revision = '0'
lt_age = '0'
lt_version = '@0@.@1@.@2@'.format(lt_current, lt_age, lt_revision)

configinc = include_directories('.')

# get suported warning flags
warning_flags = [
  '-Waggregate-return',
  '-Wunused',
  '-Warray-bounds',
  '-Wcast-align',
  '-Wclobbered',
  '-Wdeclaration-after-statement',
  '-Wduplicated-branches',
  '-Wduplicated-cond',
  '-Wempty-body',
  '-Wformat=2',
  '-Wformat-nonliteral',
  '-Wformat-security',
  '-Wformat-signedness',
  '-Wignored-qualifiers',
  '-Wimplicit-function-declaration',
  '-Wincompatible-pointer-types-discards-qualifiers',
  '-Winit-self',
  '-Wlogical-op',
  '-Wmaybe-uninitialized',
  '-Wmissing-declarations',
  '-Wmissing-format-attribute',
  '-Wmissing-include-dirs',
  '-Wmissing-noreturn',
  '-Wmissing-parameter-type',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wno-cast-function-type',
  '-Wno-error=cpp',
  '-Wno-unknown-pragmas',
  '-Wno-discarded-qualifiers',
  '-Wno-missing-field-initializers',
  '-Wno-strict-aliasing',
  '-Wno-suggest-attribute=format',
  '-Wno-unused-parameter',
  '-Wnull-dereference',
  '-Wold-style-definition',
  '-Woverride-init',
  '-Wpointer-arith',
  '-Wredundant-decls',
  '-Wreturn-type',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-aliasing',
  '-Wstrict-prototypes',
  '-Wswitch-default',
  '-Wtype-limits',
  '-Wundef',
  '-Wuninitialized',
  '-Wunused-but-set-variable',
  '-Wunused-variable',
  '-Wwrite-strings'
]
cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments(warning_flags), language : 'c')

if not meson.is_cross_build()
  add_project_arguments('-fstack-protector-strong', language : 'c')
endif

# enable full RELRO where possible
# FIXME: until https://github.com/mesonbuild/meson/issues/1140 is fixed
global_link_args = []
test_link_args = [
  '-Wl,-z,relro',
  '-Wl,-z,now',
]
foreach link_arg: test_link_args
  if cc.has_link_argument(link_arg)
    global_link_args += link_arg
  endif
endforeach
add_project_link_arguments(
  global_link_args,
  language: 'c'
)

prefix = get_option('prefix')
if host_machine.system() == 'windows'
  bindir = get_option('bindir')
  libexecdir = get_option('libexecdir')
  localstatedir = get_option('localstatedir')
  installed_test_bindir = get_option('libexecdir')
  installed_test_datadir = get_option('datadir')
else
  bindir = join_paths(prefix, get_option('bindir'))
  datadir = join_paths(prefix, get_option('datadir'))
  localstatedir = join_paths(prefix, get_option('localstatedir'))
  libexecdir = join_paths(prefix, get_option('libexecdir'))
  installed_test_bindir = join_paths(libexecdir, 'installed-tests', meson.project_name())
  installed_test_datadir = join_paths(datadir, 'installed-tests', meson.project_name())
endif
mandir = join_paths(prefix, get_option('mandir'))
localedir = join_paths(prefix, get_option('localedir'))

diffcmd = find_program('diff')
gio = dependency('gio-2.0', version : '>= 2.45.8')
giounix = dependency('gio-unix-2.0', version : '>= 2.45.8', required: false)
if giounix.found()
  conf.set('HAVE_GIO_UNIX', '1')
endif
libjsonglib = dependency('json-glib-1.0', version : '>= 1.1.1')

libjcat_deps = [
  gio,
  libjsonglib,
]

if get_option('pkcs7')
  gnutls = dependency('gnutls', version : '>= 3.6.0')
  conf.set('ENABLE_PKCS7', '1')
  libjcat_deps += gnutls
endif

if get_option('gpg')
  gpgme = cc.find_library('gpgme')
  gpgerror = cc.find_library('gpg-error')
  conf.set('ENABLE_GPG', '1')
  libjcat_deps += gpgme
  libjcat_deps += gpgerror
endif

gnome = import('gnome')

conf.set('installed_test_bindir', installed_test_bindir)
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
conf.set_quoted('JCAT_LOCALSTATEDIR', localstatedir)
conf.set_quoted('JCAT_LOCALEDIR', localedir)
conf.set_quoted('G_LOG_DOMAIN', 'Jcat')
conf.set_quoted('VERSION', meson.project_version())
configure_file(
  output : 'config.h',
  configuration : conf
)

subdir('data')
subdir('libjcat')
if get_option('gtkdoc')
  gtkdocscan = find_program('gtkdoc-scan', required : true)
  subdir('docs')
endif
