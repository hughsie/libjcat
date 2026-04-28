
jcat_src = []
if get_option('gpg')
  jcat_src += 'fu-jcat-gpg-engine.c'
endif
if get_option('gnutls_pkcs7')
  jcat_src += 'fu-jcat-gnutls-common.c'
  jcat_src += 'fu-jcat-gnutls-pkcs7-engine.c'
endif
if get_option('openssl_pkcs7')
  jcat_src += 'fu-jcat-libcrypto-common.c'
  jcat_src += 'fu-jcat-libcrypto-pkcs7-engine.c'
endif
if get_option('gnutls_ed25519')
  jcat_src += 'fu-jcat-gnutls-common.c'
  jcat_src += 'fu-jcat-gnutls-ed25519-engine.c'
endif

jcat_mapfile = 'jcat.map'
libjcat_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), jcat_mapfile)
])
libjcat = library(
  'jcat',
  sources : [
    'fwupd-jcat-blob.c',
    'fu-jcat-context.c',
    'fu-jcat-common.c',
    'fu-jcat-engine.c',
    'fu-jcat-sha1-engine.c',
    'fu-jcat-sha256-engine.c',
    'fu-jcat-sha512-engine.c',
    'fu-jcat-result.c',
    'fu-jcat-bt-verifier.c',
    'fu-jcat-bt-checkpoint.c',
    'fwupd-jcat-file.c',
    'fwupd-jcat-item.c',
    'fu-jcat-version.c',
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

if get_option('cli')
jcat_tool = executable(
  'fu-jcat-tool',
  sources : [
    'fu-jcat-common.c',
    'fu-jcat-tool.c',
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
    input : 'fu-jcat-tool.1',
    output : 'fu-jcat-tool.1',
    configuration : conf,
    install: true,
    install_dir: join_paths(mandir, 'man1'),
  )
endif
endif

if get_option('tests')
  test_deps = []
  if certtool.found()
    test_deps += colorhug_pkcs7_signature
    test_deps += colorhug_pkcs7_signature_hash
  endif
  testdatadirs = environment()
  testdatadirs.set('G_TEST_SRCDIR', testdatadir_src)
  testdatadirs.set('G_TEST_BUILDDIR', testdatadir_dst)
  e = executable(
    'fu-jcat-self-test',
    test_deps,
    sources : [
      'fu-jcat-self-test.c',
      'fu-jcat-common.c',
      'fu-jcat-context.c',
      'fu-jcat-engine.c',
      'fu-jcat-result.c',
      'fu-jcat-sha1-engine.c',
      'fu-jcat-sha256-engine.c',
      'fu-jcat-sha512-engine.c',
      jcat_src,
    ],
    include_directories : [
      configinc,
    ],
    c_args: [
      '-DSRCDIR="' + testdatadir_src + '"',
      '-DBUILDDIR="' + testdatadir_dst + '"',
    ],
    dependencies : [
      libjcat_deps,
    ],
    install : true,
    install_dir : installed_test_bindir
  )
  test('fu-jcat-self-test', e, env : testdatadirs)
endif

jcat_incdir = include_directories('.')
