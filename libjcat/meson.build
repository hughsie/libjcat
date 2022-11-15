
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
  'jcat-bt-proof.h',
  'jcat-common.h',
  'jcat-context.h',
  'jcat-engine.h',
  'jcat-file.h',
  'jcat-item.h',
  'jcat-result.h',
  'jcat-bt-verifier.h',
  'jcat-bt-checkpoint.h',
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
if get_option('ed25519')
  jcat_src += 'jcat-ed25519-engine.c'
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
    'jcat-sha512-engine.c',
    'jcat-result.c',
    'jcat-bt-verifier.c',
    'jcat-bt-checkpoint.c',
    'jcat-bt-proof.c',
    'jcat-bt-util.c',
    'jcat-file.c',
    'jcat-item.c',
    'jcat-version.c',
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

pkgg_variables = []
if get_option('gpg')
  pkgg_variables += 'supported_gpg=1'
endif
if get_option('pkcs7')
  pkgg_variables += 'supported_pkcs7=1'
endif
if get_option('ed25519')
  pkgg_variables += 'supported_ed25519=1'
endif

pkgg = import('pkgconfig')
pkgg.generate(libjcat,
  requires : [
    'gio-2.0',
    'json-glib-1.0',
  ],
  subdirs : 'libjcat-1',
  version : meson.project_version(),
  name : 'libjcat',
  filebase : 'jcat',
  description : 'libjcat is a library to read Jcat files',
  variables : pkgg_variables,
)

libjcat_dep = declare_dependency(
  link_with : libjcat,
  include_directories : [
    include_directories('.'),
    configinc,
  ],
  variables : pkgg_variables,
  dependencies : libjcat_deps
)

if get_option('introspection')
  if libjsonglib.type_name() == 'internal'
    json_glib_girtarget = subproject('json-glib').get_variable('json_glib_gir')[0]
  else
    json_glib_girtarget = 'Json-1.0'
  endif
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
      'jcat-bt-verifier.c',
      'jcat-bt-verifier.h',
      'jcat-bt-checkpoint.c',
      'jcat-bt-checkpoint.h',
      'jcat-bt-proof.c',
      'jcat-bt-proof.h',
      'jcat-bt-util.c',
      'jcat-bt-util.h',
      'jcat-version.c',
      libjcat_version_h,
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
      json_glib_girtarget,
    ],
    link_with : [
      libjcat,
    ],
    install : true
  )

  if get_option('vapi')
    gnome.generate_vapi('jcat',
      sources : jcat_gir[0],
      packages : [
        'gio-2.0',
        'json-glib-1.0'
      ],
      install : true,
    )
  endif

  python_interpreter = find_program('python3')

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
      join_paths(meson.project_source_root(), 'contrib', 'generate-version-script.py'),
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

if get_option('cli')
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
  configure_file(
    input : 'jcat-tool.1',
    output : 'jcat-tool.1',
    configuration : conf,
    install: true,
    install_dir: join_paths(mandir, 'man1'),
  )
endif
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
      'jcat-bt-proof.c',
      'jcat-bt-verifier.c',
      'jcat-bt-checkpoint.c',
      'jcat-bt-util.c',
      'jcat-sha1-engine.c',
      'jcat-sha256-engine.c',
      'jcat-sha512-engine.c',
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
