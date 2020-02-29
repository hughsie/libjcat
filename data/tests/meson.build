configure_file(
  input : 'libjcat.test.in',
  output : 'libjcat.test',
  configuration : conf,
  install: true,
  install_dir: installed_test_datadir,
)

# generate private PKCS7 key
certtool = find_program('certtool')
pkcs7_privkey = custom_target('test-privkey.pem',
  output: 'test-privkey.pem',
  command: [certtool, '--generate-privkey', '--outfile', '@OUTPUT@'],
)
subdir('pki')
subdir('colorhug')

