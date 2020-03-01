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

testdatadir_src = meson.current_source_dir()
testdatadir_dst = meson.current_build_dir()
