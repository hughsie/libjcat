install_data([
    'secret.ed25519',
    'test.btcheckpoint',
    'test.btverifier',
  ],
  install_dir: installed_test_datadir,
)

configure_file(
  input : 'libjcat.test.in',
  output : 'libjcat.test',
  configuration : conf,
  install: true,
  install_dir: installed_test_datadir,
)

# generate private PKCS7 key
certtool = find_program(['gnutls-certtool', 'certtool'], required : false)

if certtool.found()
  pkcs7_privkey = custom_target('test-privkey.pem',
    output: 'test-privkey.pem',
    command: [certtool, '--generate-privkey', '--outfile', '@OUTPUT@'],
  )
endif

subdir('pki')
subdir('colorhug')

testdatadir_src = meson.current_source_dir()
testdatadir_dst = meson.current_build_dir()
