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

Jcat can of course sign the archive with proper keys too. here we will generate
a private and public key ourselves, but you should probabluy talk to your IT
department security team an ask them how to get a user certificate that's been
signed by the corporate certificate.

Lets first generate a test private key. This should be kept secret at all times.

    $ certtool --generate-privkey --outfile test-privkey.pem

Now, lets create a public key. Change the details for your company and country.
Hint: You can use a `.cfg` file to automate this if required.
The public key can be shared freely, and can even be included in the signature.

    $ certtool --generate-self-signed --load-privkey test-privkey.pem --outfile test.pem
    Generating a self signed certificate...
    Common name: Richard Hughes
    UID: rhughes
    Organizational unit name: Engineering
    Organization name: Hughski Limited
    Locality name:
    State or province name:
    Country name (2 chars): UK
    Enter the subject's domain component (DC):
    This field should not be used in new certificates.
    E-mail:
    Enter the certificate's serial number in decimal (123) or hex (0xabcd)
    The certificate will expire in (days): 180
    Does the certificate belong to an authority? (y/N): Y
    Is this a TLS web client certificate? (y/N): N
    Will the certificate be used for IPsec IKE operations? (y/N): N
    Is this a TLS web server certificate? (y/N): N
    Enter a dnsName of the subject of the certificate:
    Enter an additional dnsName of the subject of the certificate:
    Enter a URI of the subject of the certificate:
    Enter the IP address of the subject of the certificate:
    Enter the e-mail of the subject of the certificate: rhughes@hughski.com
    Will the certificate be used for signing (required for TLS)? (Y/n): Y
    Will the certificate be used for encryption (not required for TLS)? (Y/n): N
    Will the certificate be used for data encryption? (y/N): N
    Will the certificate be used to sign OCSP requests? (y/N): N
    Will the certificate be used to sign code? (y/N): Y
    Will the certificate be used for time stamping? (y/N): N
    Will the certificate be used for email protection? (y/N): N
    Will the certificate be used to sign other certificates? (Y/n): N
    Will the certificate be used to sign CRLs? (y/N): N
    Enter the URI of the CRL distribution point:

Then we can actually use both files:

    $ jcat-tool --appstream-id com.dell sign firmware.jcat firmware.bin test.pem test-privkey.pem
    JcatFile:
      Version:               0.1
      JcatItem:
        ID:                  firmware.bin
        JcatBlob:
          Kind:              pkcs7
          Flags:             is-utf8
          AppstreamId:       com.dell
          Timestamp:         2020-03-05T12:16:30Z
          Size:              0x373
          Data:              -----BEGIN PKCS7-----
                             MIICZwYJKoZIhvcNAQcCoIICWDCCAlQCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
                             ...
                             8jggo0FbhDSs8frXhr1BHKBktOPKEbA3sETxlbHViYt6oldpi1uszV0kHA==
                             -----END PKCS7-----

Lets verify this new signature:

    jcat-tool --appstream-id com.dell verify firmware.jcat
    firmware.bin:
        FAILED pkcs7: failed to verify data for C=UK,...: Public key signature verification has failed. [-89]
        FAILED: Validation failed
    Validation failed

Ahh, of course; we need to tell Jcat to load our generated certificate:

    jcat-tool --appstream-id com.dell verify firmware.jcat --public-key test.pem
    firmware.bin:
        PASSED pkcs7: C=UK,O=Hughski Limited,OU=Engineering,UID=rhughes,CN=Richard Hughes

We can then check the result using

    $ jcat-tool export firmware.jcat
    Wrote ./firmware.bin-com.dell.p7b
    $ certtool --p7-verify --infile firmware.bin-com.dell.p7b --load-data firmware.bin --load-certificate=test.pem
    eContent Type: 1.2.840.113549.1.7.1
    Signers:
        Signer's issuer DN: C=UK,O=Hughski Limited,OU=Engineering,UID=rhughes,CN=Richard Hughes
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
