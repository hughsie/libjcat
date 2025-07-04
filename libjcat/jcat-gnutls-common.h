/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/pkcs7.h>

#include "jcat-compile.h"

typedef guchar gnutls_data_t;

static void
_gnutls_datum_deinit(gnutls_datum_t *d)
{
	gnutls_free(d->data);
	gnutls_free(d);
}

static void
jcat_gnutls_ed25519_datum_clear(gnutls_datum_t *d)
{
	gnutls_free(d->data);
}

static void
_gnutls_x509_trust_list_deinit(gnutls_x509_trust_list_t tl)
{
	gnutls_x509_trust_list_deinit(tl, 0);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_pkcs7_t, gnutls_pkcs7_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_privkey_t, gnutls_privkey_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_pubkey_t, gnutls_pubkey_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_crt_t, gnutls_x509_crt_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_dn_t, gnutls_x509_dn_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_privkey_t, gnutls_x509_privkey_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_spki_t, gnutls_x509_spki_deinit, NULL)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_data_t, gnutls_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_pkcs7_signature_info_st, gnutls_pkcs7_signature_info_deinit)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_datum_t, _gnutls_datum_deinit)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(gnutls_datum_t, jcat_gnutls_ed25519_datum_clear)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_trust_list_t, _gnutls_x509_trust_list_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_x509_trust_list_iter_t,
				gnutls_x509_trust_list_iter_deinit,
				NULL)
#pragma clang diagnostic pop

void
jcat_gnutls_global_init(void);
gchar *
jcat_gnutls_pkcs7_datum_to_dn_str(const gnutls_datum_t *raw) G_GNUC_NON_NULL(1);
gnutls_x509_crt_t
jcat_gnutls_pkcs7_load_crt_from_blob(GBytes *blob, gnutls_x509_crt_fmt_t format, GError **error)
    G_GNUC_NON_NULL(1);
gnutls_privkey_t
jcat_gnutls_pkcs7_load_privkey_from_blob(GBytes *blob, GError **error) G_GNUC_NON_NULL(1);
gnutls_pubkey_t
jcat_gnutls_pkcs7_load_pubkey_from_privkey(gnutls_privkey_t privkey, GError **error)
    G_GNUC_NON_NULL(1);
gboolean
jcat_gnutls_ensure_trust_list_valid(gnutls_x509_trust_list_t tl, GError **error) G_GNUC_NON_NULL(1);

GBytes *
jcat_gnutls_pkcs7_create_private_key(gnutls_pk_algorithm_t algo, GError **error);

GBytes *
jcat_gnutls_pkcs7_create_client_certificate(gnutls_privkey_t privkey, GError **error)
    G_GNUC_NON_NULL(1);
