install_data([
    'firmware.bin',
    'firmware.bin.asc',
    'firmware.bin.p7b',
  ],
  install_dir: join_paths(installed_test_bindir, 'colorhug'),
)

if get_option('pkcs7')
  # generate self-signed detached signature
  colorhug_pkcs7_signature = custom_target('firmware.bin.p7c',
    input: 'firmware.bin',
    output: 'firmware.bin.p7c',
    command: [certtool, '--p7-detached-sign',
                        '--p7-time',
                        '--load-privkey', pkcs7_privkey,
                        '--load-certificate', pkcs7_certificate,
                        '--infile', '@INPUT@',
                        '--outfile', '@OUTPUT@'],
    install: true,
    install_dir: join_paths(installed_test_bindir, 'colorhug'),
  )
endif
