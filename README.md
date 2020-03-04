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

    $ jcat-tool sign test.jcat firmware.bin sha256
    $ jcat-tool info test.jcat
    JcatFile:
      Version:               0.1
      JcatItem:
        ID:                  firmware.bin
        JcatBlob:
          Kind:              sha256
          Flags:             is-utf8
          Timestamp:         2020-03-04T13:59:57Z
          Size:              0x40
          Data:              bd598c9019baee65373da1963fbce7478d6e9e8963bd837d12896f53b03be83e

Now we can import both existing signatures into a Jcat file, and then validate
it again.

    $ jcat-tool import test.jcat firmware.bin firmware.bin.asc
    $ jcat-tool import test.jcat firmware.bin firmware.bin.p7b
    $ jcat-tool info test.jcat
    JcatFile:
      Version:               0.1
      JcatItem:
        ID:                  firmware.bin
        JcatBlob:
          Kind:              sha256
          Flags:             is-utf8
          Timestamp:         2020-03-04T13:59:57Z
          Size:              0x40
          Data:              bd598c9019baee65373da1963fbce7478d6e9e8963bd837d12896f53b03be83e
        JcatBlob:
          Kind:              gpg
          Flags:             is-utf8
          Timestamp:         2020-03-04T14:00:30Z
          Size:              0x1ea
          Data:              -----BEGIN PGP SIGNATURE-----
                             Version: GnuPG v2.0.22 (GNU/Linux)

                             iQEcBAABAgAGBQJeVoylAAoJEEim2A5FOLrCagQIAIb6uDCzwUBBoZRqRzekxf0E
    ...
                             =0GGy
                             -----END PGP SIGNATURE-----

        JcatBlob:
          Kind:              pkcs7
          Flags:             is-utf8
          Timestamp:         2020-03-04T14:00:34Z
          Size:              0x8c0
          Data:              -----BEGIN PKCS7-----
                             MIIGUgYJKoZIhvcNAQcCoIIGQzCCBj8CAQExDTALBglghkgBZQMEAgEwCwYJKoZI
    ...
                             EYOqoEV8PaVQZW3ndWEaQfyo6MgZ/WqpO6Gv2zTx1CXk0APIGG8=
                             -----END PKCS7-----

    $ jcat-tool verify test.jcat --public-keys /etc/pki/fwupd
    firmware.bin:
        PASSED sha256: OK
        PASSED gpg: 3FC6B804410ED0840D8F2F9748A6D80E4538BAC2
        PASSED pkcs7: O=Linux Vendor Firmware Project,CN=LVFS CA
