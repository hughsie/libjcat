
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
  jcat_src += 'jcat-engine-gpg.c'
endif
if get_option('pkcs7')
  jcat_src += 'jcat-engine-pkcs7.c'
endif

jcat_mapfile = 'jcat.map'
vflag = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), jcat_mapfile)
libjcat = shared_library(
  'jcat',
  sources : [
    'jcat-blob.c',
    'jcat-context.c',
    'jcat-common.c',
    'jcat-engine.c',
    'jcat-engine-sha256.c',
    'jcat-result.c',
    'jcat-file.c',
    'jcat-item.c',
    jcat_src,
  ],
  soversion : lt_current,
  version : lt_version,
  dependencies : [
    gio,
    libjsonglib,
    libjcat_deps,
  ],
  include_directories : root_incdir,
  link_args : vflag,
  link_depends : jcat_mapfile,
  install : true
)

pkgg = import('pkgconfig')
pkgg.generate(
  libraries : libjcat,
  requires : [ 'gio-2.0' ],
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
    root_incdir,
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
      giounix,
    ],
    includes : [
      'Gio-2.0',
      'GObject-2.0',
    ],
    install : true
  )

  gnome.generate_vapi('jcat',
    sources : jcat_gir[0],
    packages : ['gio-2.0'],
    install : true,
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
    root_incdir,
  ],
  dependencies : [
    giounix,
    libjsonglib,
  ],
  link_with : [
    libjcat,
  ],
  install : true,
  install_dir : libexecdir,
)

if get_option('tests')
  test_deps = []
  if get_option('pkcs7')
    test_deps += colorhug_pkcs7_signature
  endif
  e = executable(
    'jcat-self-test',
    test_deps,
    sources : [
      'jcat-self-test.c',
      'jcat-blob.c',
      'jcat-context.c',
      'jcat-common.c',
      'jcat-engine.c',
      'jcat-engine-sha256.c',
      'jcat-result.c',
      'jcat-file.c',
      'jcat-item.c',
      jcat_src,
    ],
    include_directories : [
      root_incdir,
    ],
    dependencies : [
      gio,
      libjsonglib,
      libjcat_deps,
    ],
    c_args : [
      '-DTESTDATADIR_SRC="' + testdatadir_src + '"',
      '-DTESTDATADIR_DST="' + testdatadir_dst + '"',
    ],
    install : false,
  )
  test('jcat-self-test', e)
endif

jcat_incdir = include_directories('.')
