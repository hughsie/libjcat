libjcat
=======

This library allows reading and writing gzip-compressed JSON catalog files,
which can be used to store GPG, PKCS-7 and SHA-256 checksums for each file.

This provides equivalent functionality to the catalog files supported in
Microsoft Windows.

Design
======

Each JSON file is gzipped, and is logically divided into three structures:

JcatBlob
--------

The 'signature' blob, which can be a proper detached sigature like PKCS-7 or
just a checksum like SHA-256.

JcatItem
--------

Items roughly approximate single files, and can have multiple JcatBlobs assigned.
In a typical firmware archive you would have two items, with IDs `firmware.bin`
and `firmware.metainfo.xml`

JcatFile
--------

The container which contains one or multiple JcatItems.

Testing
=======

Download a firmware from the LVFS, and decompress with `gcab -x` -- we can now
validate the signatures are valid:

    certtool --p7-verify --infile=firmware.bin.p7b --load-ca-certificate=/etc/pki/fwupd/LVFS-CA.pem --load-data=firmware.bin

Lets create a Jcat file with a single checksum:

    $ jcat sign test.jcat firmware.bin sha256
    $ jcat info test.jcat
      Version:        0.1
        ID:           firmware.bin
          Kind:       sha256
          Data:       bd598c9019baee65373da1963fbce7478d6e9e8963bd837d12896f53b03be83e
          DataSz:     64

Now we can import both existing signatures into a Jcat file, and then validate
it again.

    $ jcat import test.jcat firmware.bin firmware.bin.asc gpg
    $ jcat import test.jcat firmware.bin firmware.bin.p7b pkcs7
    $ jcat info test.jcat
    $ jcat verify test.jcat --public-keys /etc/pki/fwupd
      firmware.bin:
        PASSED gpg: 3FC6B804410ED0840D8F2F9748A6D80E4538BAC2
        PASSED pkcs7: O=Linux Vendor Firmware Project,CN=LVFS CA
        PASSED sha256: OK
