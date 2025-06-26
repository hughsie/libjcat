/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2025 Colin Kinloch <colin.kinloch@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

// Maybe remove this or set OPENSSL_API_COMPAT to a reasonable version
#define OPENSSL_NO_DEPRECATED

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>

#include "jcat-compile.h"

typedef STACK_OF(X509) STACK_OF_X509;
void STACK_OF_X509_free(STACK_OF_X509 *stack);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_VERIFY_PARAM, X509_VERIFY_PARAM_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_PUBKEY, X509_PUBKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_EXTENSION, X509_EXTENSION_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_X509, STACK_OF_X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(PKCS7, PKCS7_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CMS_ContentInfo, CMS_ContentInfo_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_DECODER_CTX, OSSL_DECODER_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_ENCODER_CTX, OSSL_ENCODER_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_INTEGER, ASN1_INTEGER_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_TIME, ASN1_TIME_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_OCTET_STRING, ASN1_OCTET_STRING_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free)
#pragma clang diagnostic pop

X509 *
jcat_pkcs7_load_crt_from_blob_pem(GBytes *blob, GError **error) G_GNUC_NON_NULL(1);
X509 *
jcat_pkcs7_load_crt_from_blob_der(GBytes *blob, GError **error) G_GNUC_NON_NULL(1);
EVP_PKEY *
jcat_pkcs7_load_privkey_from_blob_pem(GBytes *blob, GError **error) G_GNUC_NON_NULL(1);

GBytes *
jcat_pkcs7_create_private_key(GError **error);
GBytes *
jcat_pkcs7_create_client_certificate(EVP_PKEY *privkey, GError **error) G_GNUC_NON_NULL(1);

gchar *
jcat_pkcs7_get_errors(void);
GBytes *
jcat_pkcs7_bio_to_bytes(BIO *bio);
