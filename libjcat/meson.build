
libjcat_version_h = configure_file(
  input : 'jcat-version.h.in',
  output : 'jcat-version.h',
  configuration : conf
)

install_headers(
  'jcat.h',
  subdir : 'libjcat-1',
)

jcat_headers = files(
  'jcat-blob.h',
  'jcat-common.h',
  'jcat-context.h',
  'jcat-engine.h',
  'jcat-file.h',
  'jcat-item.h',
  'jcat-result.h',
) + [libjcat_version_h]

install_headers(
  jcat_headers,
  subdir : 'libjcat-1/libjcat',
)

jcat_src = []
if get_option('gpg')
  jcat_src += 'jcat-gpg-engine.c'
endif
if get_option('pkcs7')
  jcat_src += 'jcat-pkcs7-common.c'
  jcat_src += 'jcat-pkcs7-engine.c'
endif

jcat_mapfile = 'jcat.map'
libjcat_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), jcat_mapfile)
])
libjcat = library(
  'jcat',
  sources : [
    'jcat-blob.c',
    'jcat-context.c',
    'jcat-common.c',
    'jcat-engine.c',
    'jcat-sha1-engine.c',
    'jcat-sha256-engine.c',
    'jcat-result.c',
    'jcat-file.c',
    'jcat-item.c',
    jcat_src,
  ],
  soversion : lt_current,
  version : lt_version,
  include_directories : configinc,
  dependencies : libjcat_deps,
  link_args : libjcat_ldflags,
  link_depends : jcat_mapfile,
  install : true
)

pkgg = import('pkgconfig')
pkgg.generate(
  libraries : libjcat,
  requires : [
    'gio-2.0',
    'json-glib-1.0',
  ],
  subdirs : 'libjcat-1',
  version : meson.project_version(),
  name : 'libjcat',
  filebase : 'jcat',
  description : 'libjcat is a library to read Jcat files',
)

libjcat_dep = declare_dependency(
  link_with : libjcat,
  include_directories : [
    include_directories('.'),
    configinc,
  ],
  dependencies : libjcat_deps
)

if get_option('introspection')
  jcat_gir = gnome.generate_gir(libjcat,
    sources : [
      'jcat-blob.c',
      'jcat-blob.h',
      'jcat-common.c',
      'jcat-common.h',
      'jcat-file.c',
      'jcat-file.h',
      'jcat-item.c',
      'jcat-item.h',
      'jcat-context.c',
      'jcat-context.h',
      'jcat-engine.c',
      'jcat-engine.h',
      'jcat-result.c',
      'jcat-result.h',
    ],
    nsversion : '1.0',
    namespace : 'Jcat',
    symbol_prefix : 'jcat',
    identifier_prefix : 'Jcat',
    export_packages : 'jcat',
    header : 'jcat.h',
    dependencies : [
      libjcat_deps,
    ],
    includes : [
      'Gio-2.0',
      'GObject-2.0',
      'Json-1.0',
    ],
    link_with : [
      libjcat,
    ],
    install : true
  )

  gnome.generate_vapi('jcat',
    sources : jcat_gir[0],
    packages : [
      'gio-2.0',
      'json-glib-1.0'
    ],
    install : true,
  )

  python = import('python')
  python_interpreter = python.find_installation('python3',
    modules: [
      'xml.etree.ElementTree',
      'pkg_resources',
    ],
  )

  # Verify the map file is correct -- note we can't actually use the generated
  # file for two reasons:
  #
  #  1. We don't hard depend on GObject Introspection
  #  2. The map file is required to build the lib that the GIR is built from
  #
  # To avoid the circular dep, and to ensure we don't change exported API
  # accidentally actually check in a version of the version script to git.
  mapfile_target = custom_target('jcat_mapfile',
    input: jcat_gir[0],
    output: 'jcat.map',
    command: [
      python_interpreter,
      join_paths(meson.source_root(), 'contrib', 'generate-version-script.py'),
      'LIBJCAT',
      '@INPUT@',
      '@OUTPUT@',
    ],
  )
  test('jcat-exported-api', diffcmd,
       args : [
        '-urNp',
        join_paths(meson.current_source_dir(), 'jcat.map'),
        mapfile_target,
        ],
      )
endif

jcat_tool = executable(
  'jcat-tool',
  sources : [
    'jcat-common.c',
    'jcat-tool.c',
  ],
  include_directories : [
    configinc,
  ],
  dependencies : [
    giounix,
    libjsonglib,
  ],
  link_with : [
    libjcat,
  ],
  install : true,
  install_dir : bindir,
)

if get_option('man')
  help2man = find_program('help2man')
  custom_target('jcat-tool-man',
    input : jcat_tool,
    output : 'jcat-tool.1',
    command : [
      help2man, '@INPUT@',
      '--no-info',
      '--output', '@OUTPUT@',
      '--name', 'Standalone detached signature utility',
      '--manual', 'User Commands',
      '--version-string', libjcat_version,
    ],
    install : true,
    install_dir : join_paths(mandir, 'man1'),
  )
endif

if get_option('tests')
  test_deps = []
  if get_option('pkcs7')
    test_deps += colorhug_pkcs7_signature
  endif
  testdatadirs = environment()
  testdatadirs.set('G_TEST_SRCDIR', testdatadir_src)
  testdatadirs.set('G_TEST_BUILDDIR', testdatadir_dst)
  e = executable(
    'jcat-self-test',
    test_deps,
    sources : [
      'jcat-self-test.c',
      'jcat-blob.c',
      'jcat-common.c',
      'jcat-context.c',
      'jcat-engine.c',
      'jcat-file.c',
      'jcat-item.c',
      'jcat-result.c',
      'jcat-sha1-engine.c',
      'jcat-sha256-engine.c',
      jcat_src,
    ],
    include_directories : [
      configinc,
    ],
    dependencies : [
      libjcat_deps,
    ],
    install : true,
    install_dir : installed_test_bindir
  )
  test('jcat-self-test', e, env : testdatadirs)
endif

jcat_incdir = include_directories('.')
