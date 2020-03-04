/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/pkcs7.h>

#include "jcat-common-private.h"
#include "jcat-engine-pkcs7.h"
#include "jcat-engine-private.h"

struct _JcatEnginePkcs7
{
	JcatEngine			 parent_instance;
	gnutls_x509_trust_list_t	 tl;
};

G_DEFINE_TYPE (JcatEnginePkcs7, jcat_engine_pkcs7, JCAT_TYPE_ENGINE)

typedef guchar gnutls_data_t;

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
#pragma clang diagnostic pop

static gnutls_x509_crt_t
jcat_engine_pkcs7_load_crt_from_filename (const gchar *filename,
					 gnutls_x509_crt_fmt_t format,
					 GError **error)
{
	gnutls_datum_t d = { 0 };
	gsize bufsz = 0;
	int rc;
	g_autofree gchar *buf = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;

	/* create certificate */
	rc = gnutls_x509_crt_init (&crt);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* import the certificate */
	if (!g_file_get_contents (filename, &buf, &bufsz, error))
		return NULL;
	d.size = bufsz;
	d.data = (unsigned char *) buf;
	rc = gnutls_x509_crt_import (crt, &d, GNUTLS_X509_FMT_PEM);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_import: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}
	return g_steal_pointer (&crt);
}

static gboolean
jcat_engine_pkcs7_add_pubkey (JcatEnginePkcs7 *self,
			      const gchar *filename,
			      gnutls_x509_crt_fmt_t format,
			      GError **error)
{
	guint key_usage = 0;
	int rc;
	g_auto(gnutls_x509_crt_t) crt = NULL;

	/* load file and add to the trust list */
	g_debug ("trying to load certificate from %s", filename);
	crt = jcat_engine_pkcs7_load_crt_from_filename (filename, format, error);
	if (crt == NULL)
		return FALSE;
	rc = gnutls_x509_crt_get_key_usage (crt, &key_usage, NULL);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to get key usage: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	if ((key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE) == 0 &&
	    (key_usage & GNUTLS_KEY_KEY_CERT_SIGN) == 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "certificate %s not suitable for use [0x%x]",
			     filename, key_usage);
		return FALSE;
	}
	rc = gnutls_x509_trust_list_add_cas (self->tl, &crt, 1, 0);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to add to trust list: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	g_debug ("loaded %i certificates", rc);

	/* confusingly the trust list does not copy the certificate */
	crt = NULL;
	return TRUE;
}

static gboolean
jcat_engine_pkcs7_add_public_key (JcatEngine *engine,
				  const gchar *filename,
				  GError **error)
{
	JcatEnginePkcs7 *self = JCAT_ENGINE_PKCS7 (engine);

	/* search all the public key files */
	if (g_str_has_suffix (filename, ".pem")) {
		if (!jcat_engine_pkcs7_add_pubkey (self, filename,
						   GNUTLS_X509_FMT_PEM,
						   error))
			return FALSE;
	} else if (g_str_has_suffix (filename, ".cer") ||
		   g_str_has_suffix (filename, ".crt") ||
		   g_str_has_suffix (filename, ".der")) {
		if (!jcat_engine_pkcs7_add_pubkey (self, filename,
						   GNUTLS_X509_FMT_DER,
						   error))
			return FALSE;
	} else {
		g_autofree gchar *basename = g_path_get_basename (filename);
		g_debug ("ignoring %s as not PKCS-7 certificate", basename);
	}
	return TRUE;
}

static gnutls_privkey_t
jcat_engine_pkcs7_load_privkey (JcatEnginePkcs7 *self, GError **error)
{
	JcatEngine *engine = JCAT_ENGINE (self);
	int rc;
	gnutls_datum_t d = { 0 };
	gsize bufsz = 0;
	g_autofree gchar *buf = NULL;
	g_autofree gchar *fn = NULL;
	g_auto(gnutls_privkey_t) key = NULL;

	/* load the private key */
	rc = gnutls_privkey_init (&key);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}
	fn = g_build_filename (jcat_engine_get_keyring_path (engine), "pki", "secret.key", NULL);
	if (!g_file_get_contents (fn, &buf, &bufsz, error))
		return NULL;
	d.size = bufsz;
	d.data = (unsigned char *) buf;
	rc = gnutls_privkey_import_x509_raw (key, &d, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_import_x509_raw: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}
	return g_steal_pointer (&key);
}

static gnutls_x509_crt_t
jcat_engine_pkcs7_load_client_certificate (JcatEnginePkcs7 *self, GError **error)
{
	JcatEngine *engine = JCAT_ENGINE (self);
	g_autofree gchar *filename = NULL;
	filename = g_build_filename (jcat_engine_get_keyring_path (engine),
				     "pki", "client.pem", NULL);
	return jcat_engine_pkcs7_load_crt_from_filename (filename,
							GNUTLS_X509_FMT_PEM,
							error);
}

static gnutls_pubkey_t
jcat_engine_pkcs7_load_pubkey_from_privkey (gnutls_privkey_t privkey, GError **error)
{
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	int rc;

	/* get the public key part of the private key */
	rc = gnutls_pubkey_init (&pubkey);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "pubkey_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}
	rc = gnutls_pubkey_import_privkey (pubkey, privkey, 0, 0);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "pubkey_import_privkey: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* success */
	return g_steal_pointer (&pubkey);
}

/* generates a private key just like:
 *  `certtool --generate-privkey` */
static gboolean
jcat_engine_pkcs7_ensure_private_key (JcatEnginePkcs7 *self, GError **error)
{
	JcatEngine *engine = JCAT_ENGINE (self);
	gnutls_datum_t d = { 0 };
	int bits;
	int key_type = GNUTLS_PK_RSA;
	int rc;
	g_autofree gchar *fn = NULL;
	g_auto(gnutls_x509_privkey_t) key = NULL;
	g_auto(gnutls_x509_spki_t) spki = NULL;
	g_autoptr(GFile) file = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* check exists */
	fn = g_build_filename (jcat_engine_get_keyring_path (engine),
			       "pki", "secret.key", NULL);
	if (g_file_test (fn, G_FILE_TEST_EXISTS))
		return TRUE;

	/* create parents if required */
	if (!jcat_mkdir_parent (fn, error))
		return FALSE;

	/* initialize key and SPKI */
	rc = gnutls_x509_privkey_init (&key);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	rc = gnutls_x509_spki_init (&spki);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "spki_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* generate key */
	bits = gnutls_sec_param_to_pk_bits (key_type, GNUTLS_SEC_PARAM_HIGH);
	g_debug ("generating a %d bit %s private key...",
		 bits, gnutls_pk_algorithm_get_name (key_type));
	rc = gnutls_x509_privkey_generate2(key, key_type, bits, 0, NULL, 0);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_generate2: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	rc = gnutls_x509_privkey_verify_params (key);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_verify_params: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* save to file */
	rc = gnutls_x509_privkey_export2 (key, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "privkey_export2: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	d_payload = d.data;
	file = g_file_new_for_path (fn);
	return g_file_replace_contents (file, (const char *) d_payload, d.size,
					NULL, FALSE, G_FILE_CREATE_PRIVATE, NULL,
					NULL, error);
}

/* generates a self signed certificate just like:
 *  `certtool --generate-self-signed --load-privkey priv.pem` */
static gboolean
jcat_engine_pkcs7_ensure_client_certificate (JcatEnginePkcs7 *self, GError **error)
{
	JcatEngine *engine = JCAT_ENGINE (self);
	int rc;
	gnutls_datum_t d = { 0 };
	guchar sha1buf[20];
	gsize sha1bufsz = sizeof(sha1buf);
	g_autofree gchar *fn = NULL;
	g_auto(gnutls_privkey_t) key = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* check exists */
	fn = g_build_filename (jcat_engine_get_keyring_path (engine),
			       "pki", "client.pem", NULL);
	if (g_file_test (fn, G_FILE_TEST_EXISTS))
		return TRUE;

	/* ensure the private key exists */
	if (!jcat_engine_pkcs7_ensure_private_key (self, error)) {
		g_prefix_error (error, "failed to generate private key: ");
		return FALSE;
	}

	/* load private key */
	key = jcat_engine_pkcs7_load_privkey (self, error);
	if (key == NULL)
		return FALSE;

	/* load the public key from the private key */
	pubkey = jcat_engine_pkcs7_load_pubkey_from_privkey (key, error);
	if (pubkey == NULL)
		return FALSE;

	/* create certificate */
	rc = gnutls_x509_crt_init (&crt);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set public key */
	rc = gnutls_x509_crt_set_pubkey (crt, pubkey);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_set_pubkey: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set positive random serial number */
	rc = gnutls_rnd (GNUTLS_RND_NONCE, sha1buf, sizeof(sha1buf));
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "gnutls_rnd: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	sha1buf[0] &= 0x7f;
	rc = gnutls_x509_crt_set_serial(crt, sha1buf, sizeof(sha1buf));
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_set_serial: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set activation */
	rc = gnutls_x509_crt_set_activation_time (crt, time (NULL));
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "set_activation_time: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set expiration */
	rc = gnutls_x509_crt_set_expiration_time (crt, (time_t) -1);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "set_expiration_time: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set basic constraints */
	rc = gnutls_x509_crt_set_basic_constraints (crt, 0, -1);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "set_basic_constraints: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set usage */
	rc = gnutls_x509_crt_set_key_usage (crt, GNUTLS_KEY_DIGITAL_SIGNATURE);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "set_key_usage: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set subject key ID */
	rc = gnutls_x509_crt_get_key_id (crt, GNUTLS_KEYID_USE_SHA1, sha1buf, &sha1bufsz);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "get_key_id: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	rc = gnutls_x509_crt_set_subject_key_id (crt, sha1buf, sha1bufsz);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "set_subject_key_id: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* set version */
	rc = gnutls_x509_crt_set_version (crt, 3);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "error setting certificate version: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* self-sign certificate */
	rc = gnutls_x509_crt_privkey_sign (crt, crt, key, GNUTLS_DIG_SHA256, 0);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_privkey_sign: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}

	/* export to file */
	rc = gnutls_x509_crt_export2 (crt, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "crt_export2: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	d_payload = d.data;
	return g_file_set_contents (fn, (const gchar *) d_payload, d.size, error);
}

static gboolean
jcat_engine_pkcs7_setup (JcatEngine *engine, GError **error)
{
	JcatEnginePkcs7 *self = JCAT_ENGINE_PKCS7 (engine);
	int rc;

	if (self->tl != NULL)
		return TRUE;

	/* create trust list, a bit like a engine */
	rc = gnutls_x509_trust_list_init (&self->tl, 0);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to create trust list: %s [%i]",
			     gnutls_strerror (rc), rc);
		return FALSE;
	}
	return TRUE;
}

static void
_gnutls_datum_deinit (gnutls_datum_t *d)
{
	gnutls_free (d->data);
	gnutls_free (d);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_datum_t, _gnutls_datum_deinit)
#pragma clang diagnostic pop

static gchar *
jcat_engine_pkcs7_datum_to_dn_str (const gnutls_datum_t *raw)
{
	g_auto(gnutls_x509_dn_t) dn = NULL;
	g_autoptr(gnutls_datum_t) str = NULL;
	int rc;
	rc = gnutls_x509_dn_init (&dn);
	if (rc < 0)
		return NULL;
	rc = gnutls_x509_dn_import (dn, raw);
	if (rc < 0)
		return NULL;
	str = (gnutls_datum_t *) gnutls_malloc (sizeof (gnutls_datum_t));
	str->data = NULL;
	rc = gnutls_x509_dn_get_str2 (dn, str, 0);
	if (rc < 0)
		return NULL;
	return g_strndup ((const gchar *) str->data, str->size);
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_engine_pkcs7_verify_data (JcatEngine *engine,
			     GBytes *blob,
			     GBytes *blob_signature,
			     JcatVerifyFlags flags,
			     GError **error)
{
	JcatEnginePkcs7 *self = JCAT_ENGINE_PKCS7 (engine);
	gnutls_datum_t datum = { 0 };
	gint64 timestamp_newest = 0;
	gnutls_pkcs7_signature_info_st info_tmp = { 0x0 };
	int count;
	int rc;
	g_auto(gnutls_pkcs7_t) pkcs7 = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(GString) authority_newest = g_string_new (NULL);

	/* startup */
	rc = gnutls_pkcs7_init (&pkcs7);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to init pkcs7: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* import the signature */
	datum.data = (guchar *) g_bytes_get_data (blob_signature, NULL);
	datum.size = g_bytes_get_size (blob_signature);
	rc = gnutls_pkcs7_import (pkcs7, &datum, GNUTLS_X509_FMT_PEM);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to import the PKCS7 signature: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* verify the blob */
	datum.data = (guchar *) g_bytes_get_data (blob, NULL);
	datum.size = g_bytes_get_size (blob);
	count = gnutls_pkcs7_get_signature_count (pkcs7);
	g_debug ("got %i PKCS7 signatures", count);
	if (count == 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "no PKCS7 signatures found");
		return NULL;
	}

	/* use client certificate */
	if (flags & JCAT_VERIFY_FLAG_USE_CLIENT_CERT) {
		if (!jcat_engine_pkcs7_ensure_client_certificate (self, error)) {
			g_prefix_error (error, "failed to generate client certificate: ");
			return NULL;
		}
		crt = jcat_engine_pkcs7_load_client_certificate (self, error);
		if (crt == NULL)
			return NULL;
	}

	for (gint i = 0; i < count; i++) {
		g_autoptr(gnutls_pkcs7_signature_info_st) info = &info_tmp;
		gint64 signing_time = 0;
		gnutls_certificate_verify_flags verify_flags = 0;
		g_autofree gchar *dn = NULL;

		/* use with care */
		if (flags & JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS) {
			g_debug ("WARNING: disabling time checks");
			verify_flags |= GNUTLS_VERIFY_DISABLE_TIME_CHECKS;
			verify_flags |= GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS;
		}

		/* always get issuer */
		rc = gnutls_pkcs7_get_signature_info (pkcs7, i, &info_tmp);
		if (rc < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "failed to get signature info: %s [%i]",
				     gnutls_strerror (rc), rc);
			return NULL;
		}

		/* verify the data against the detached signature */
		if (flags & JCAT_VERIFY_FLAG_USE_CLIENT_CERT) {
			rc = gnutls_pkcs7_verify_direct (pkcs7, crt, i, &datum, 0);
		} else {
			rc = gnutls_pkcs7_verify (pkcs7, self->tl,
						  NULL, /* vdata */
						  0,    /* vdata_size */
						  i,    /* index */
						  &datum, /* data */
						  verify_flags);
		}
		if (rc < 0) {
			dn = jcat_engine_pkcs7_datum_to_dn_str (&info->issuer_dn);
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "failed to verify data for %s: %s [%i]",
				     dn, gnutls_strerror (rc), rc);
			return NULL;
		}

		/* save details about the key for the result */
		signing_time = info->signing_time > 0 ? (gint64) info->signing_time : 1;
		if (signing_time > timestamp_newest) {
			timestamp_newest = signing_time;
			dn = jcat_engine_pkcs7_datum_to_dn_str (&info->issuer_dn);
			if (dn != NULL)
				g_string_assign (authority_newest, dn);
		}
	}

	/* success */
	return JCAT_RESULT (g_object_new (JCAT_TYPE_RESULT,
					  "engine", engine,
					  "timestamp", timestamp_newest,
					  "authority", authority_newest->str,
					  NULL));
}

/* creates a detached signature just like:
 *  `certtool --p7-detached-sign --load-certificate client.pem \
 *    --load-privkey secret.pem --outfile=test.p7b` */
static GBytes *
jcat_engine_pkcs7_sign_data (JcatEngine *engine,
			    GBytes *blob,
			    JcatSignFlags flags,
			    GError **error)
{
	JcatEnginePkcs7 *self = JCAT_ENGINE_PKCS7 (engine);
	gnutls_datum_t d = { 0 };
	gnutls_digest_algorithm_t dig = GNUTLS_DIG_NULL;
	guint gnutls_flags = 0;
	int rc;
	g_auto(gnutls_pkcs7_t) pkcs7 = NULL;
	g_auto(gnutls_privkey_t) key = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* ensure the client certificate exists */
	if (!jcat_engine_pkcs7_ensure_client_certificate (self, error)) {
		g_prefix_error (error, "failed to generate client certificate: ");
		return NULL;
	}

	/* import the keys */
	crt = jcat_engine_pkcs7_load_client_certificate (self, error);
	if (crt == NULL)
		return NULL;
	key = jcat_engine_pkcs7_load_privkey (self, error);
	if (key == NULL)
		return NULL;

	/* get the digest algorithm from the publix key */
	pubkey = jcat_engine_pkcs7_load_pubkey_from_privkey (key, error);
	if (pubkey == NULL)
		return NULL;
	rc = gnutls_pubkey_get_preferred_hash_algorithm (pubkey, &dig, NULL);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "preferred_hash_algorithm: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* create container */
	rc = gnutls_pkcs7_init (&pkcs7);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "pkcs7_init: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* sign data */
	d.data = (unsigned char *) g_bytes_get_data (blob, NULL);
	d.size = g_bytes_get_size (blob);
	if (flags & JCAT_SIGN_FLAG_ADD_TIMESTAMP)
		gnutls_flags |= GNUTLS_PKCS7_INCLUDE_TIME;
	if (flags & JCAT_SIGN_FLAG_ADD_CERT)
		gnutls_flags |= GNUTLS_PKCS7_INCLUDE_CERT;
	rc = gnutls_pkcs7_sign (pkcs7, crt, key, &d, NULL, NULL, dig, gnutls_flags);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "pkcs7_sign: %s [%i]",
			     gnutls_strerror (rc), rc);
		return NULL;
	}

	/* set certificate */
	if (flags & JCAT_SIGN_FLAG_ADD_CERT) {
		rc = gnutls_pkcs7_set_crt (pkcs7, crt);
		if (rc < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "pkcs7_set_cr: %s", gnutls_strerror (rc));
			return NULL;
		}
	}

	/* export */
	rc = gnutls_pkcs7_export2 (pkcs7, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "pkcs7_export: %s", gnutls_strerror (rc));
		return NULL;
	}
	d_payload = d.data;
	return g_bytes_new (d_payload, d.size);
}

static void
jcat_engine_pkcs7_finalize (GObject *object)
{
	JcatEnginePkcs7 *self = JCAT_ENGINE_PKCS7 (object);
	gnutls_x509_trust_list_deinit (self->tl, 1);
	G_OBJECT_CLASS (jcat_engine_pkcs7_parent_class)->finalize (object);
}

static void
jcat_engine_pkcs7_class_init (JcatEnginePkcs7Class *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS (klass);
	klass_app->setup = jcat_engine_pkcs7_setup;
	klass_app->add_public_key = jcat_engine_pkcs7_add_public_key;
	klass_app->sign_data = jcat_engine_pkcs7_sign_data;
	klass_app->verify_data = jcat_engine_pkcs7_verify_data;
	object_class->finalize = jcat_engine_pkcs7_finalize;
}

static void
jcat_engine_pkcs7_init (JcatEnginePkcs7 *self)
{
}

JcatEngine *
jcat_engine_pkcs7_new (JcatContext *context)
{
	g_return_val_if_fail (JCAT_IS_CONTEXT (context), NULL);
	return JCAT_ENGINE (g_object_new (JCAT_TYPE_ENGINE_PKCS7,
					  "context", context,
					  "kind", JCAT_BLOB_KIND_PKCS7,
					  "verify-kind", JCAT_ENGINE_VERIFY_KIND_SIGNATURE,
					  NULL));
}
