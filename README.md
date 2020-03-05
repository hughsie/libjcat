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

Self Signing
============

Jcat files can be signed using a certificate and key that are automatically
generated on your local computer. This means you can only verify the Jcat
archive on the same computer (and probably the same user) that you use to sign
the archive.

It does however mean you can skip manually generating a secret key and public
key pair. If you do upload the public certificate up to a web service (for
instance the LVFS) it does mean it can verify your signatures.

    $ jcat-tool --appstream-id localhost self-sign firmware.jcat firmware.bin
    $ jcat-tool info firmware.jcat
    JcatFile:
      Version:               0.1
      JcatItem:
        ID:                  firmware.bin
        JcatBlob:
          Kind:              pkcs7
          Flags:             is-utf8
          AppstreamId:       localhost
          Timestamp:         2020-03-05T12:06:42Z
          Size:              0x2d9
          Data:              -----BEGIN PKCS7-----
                             MIIB9wYJKoZIhvcNAQcCoIIB6DCCAeQCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
                             ...
                             oDd2UcfqgdQnihpYf0NaPDYhpcP5r7dmH1XN
                             -----END PKCS7-----

Public Key Signing
==================

Jcat can of course sign the archive with proper keys too. Here we will generate
a private and public key ourselves, but you should probably talk to your IT
department security team and ask them how to get a user certificate that's been
signed by the corporate CA certificate.

Lets create our own certificate authority (CA) and issue a per-user key for
local testing. Never use these in any kind of production system!

    $ ../contrib/build-certs.py
    $ ls ACME-CA.* rhughes*
    ACME-CA.key  ACME-CA.pem  rhughes.csr  rhughes.key  rhughes.pem  rhughes_signed.pem

Then we can actually use both files:

    $ jcat-tool --appstream-id com.redhat.rhughes sign firmware.jcat firmware.bin rhughes_signed.pem rhughes.key
    JcatFile:
      Version:               0.1
      JcatItem:
        ID:                  firmware.bin
        JcatBlob:
          Kind:              pkcs7
          Flags:             is-utf8
          AppstreamId:       com.redhat.rhughes
          Timestamp:         2020-03-05T12:16:30Z
          Size:              0x373
          Data:              -----BEGIN PKCS7-----
                             MIICZwYJKoZIhvcNAQcCoIICWDCCAlQCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
                             ...
                             8jggo0FbhDSs8frXhr1BHKBktOPKEbA3sETxlbHViYt6oldpi1uszV0kHA==
                             -----END PKCS7-----

Lets verify this new signature:

    $ jcat-tool --appstream-id com.redhat.rhughes verify firmware.jcat
    firmware.bin:
        FAILED pkcs7: failed to verify data for O=ACME Corp.,CN=ACME CA: Public key signature verification has failed. [-89]
        FAILED: Validation failed
    Validation failed

Ahh, of course; we need to tell Jcat to load our generated CA certificate:

    $ jcat-tool --appstream-id com.redhat.rhughes verify firmware.jcat --public-key ACME-CA.pem
    firmware.bin:
        PASSED pkcs7: O=ACME Corp.,CN=ACME CA

We can then check the result using

    $ jcat-tool export firmware.jcat
    Wrote ./firmware.bin-com.redhat.rhughes.p7b
    $ certtool --p7-verify --infile firmware.bin-com.redhat.rhughes.p7b --load-data firmware.bin --load-ca-certificate=ACME-CA.pem
    Loaded CAs (1 available)
    eContent Type: 1.2.840.113549.1.7.1
    Signers:
        Signer's issuer DN: O=ACME Corp.,CN=ACME CA
        Signer's serial: 4df758978d0601c6500ab6f266963916d8b7ab33
        Signature Algorithm: RSA-SHA256
        Signature status: ok

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

Security
========

Unlike Microsoft catalog files which are a signed manifest of hashes, a Jcat file
is a manifest of signatures. This means it's possible (and positively encouraged)
to modify the `.jcat` file to add new signatures or replace existing ones.

This means Jcat does not verify that the set of file has not been modified, only
that the individual files and signatures themselves have not been changed.

If you require some trust in that file A was signed at the same time, or by the
same person as file B then then best way to do this is to embed a checksum (e.g
SHA-256) into one file and then verify it in the client software.

For instance, when installing firmware we need to know if a metadata file was
provided by the LVFS with the vendor firmware file. To do this, we add the
SHA-256 checksum of the `firmware.bin` in the `firmware.metainfo.xml` file itself,
and then add both files to a Jcat archive.
The client software (e.g. fwupd) then needs to check the firmware checksum as
an additional step of verifying the signatures in the Jcat file.
