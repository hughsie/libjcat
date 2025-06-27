/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-engine-private.h"
#include "jcat-gnutls-common.h"
#include "jcat-gnutls-pkcs7-engine.h"

#ifdef HAVE_GNUTLS
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#endif

struct _JcatGnutlsPkcs7Engine {
	JcatEngine parent_instance;
	gnutls_x509_trust_list_t tl;
};

G_DEFINE_TYPE(JcatGnutlsPkcs7Engine, jcat_gnutls_pkcs7_engine, JCAT_TYPE_ENGINE)

static gboolean
jcat_gnutls_pkcs7_engine_add_pubkey_blob_fmt(JcatGnutlsPkcs7Engine *self,
					     GBytes *blob,
					     gnutls_x509_crt_fmt_t format,
					     GError **error)
{
	guint key_usage = 0;
	int rc;
	g_auto(gnutls_x509_crt_t) crt = NULL;

	/* load file and add to the trust list */
	crt = jcat_gnutls_pkcs7_load_crt_from_blob(blob, format, error);
	if (crt == NULL)
		return FALSE;
	rc = gnutls_x509_crt_get_key_usage(crt, &key_usage, NULL);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to get key usage: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return FALSE;
	}
	if ((key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE) == 0 &&
	    (key_usage & GNUTLS_KEY_KEY_CERT_SIGN) == 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "certificate not suitable for use [0x%x]",
			    key_usage);
		return FALSE;
	}
	rc = gnutls_x509_trust_list_add_cas(self->tl, &crt, 1, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to add to trust list: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return FALSE;
	}
	g_debug("loaded %i certificates", rc);

	/* confusingly the trust list does not copy the certificate */
	crt = NULL;
	return TRUE;
}

static gboolean
jcat_gnutls_pkcs7_engine_add_public_key_raw(JcatEngine *engine, GBytes *blob, GError **error)
{
	JcatGnutlsPkcs7Engine *self = JCAT_GNUTLS_PKCS7_ENGINE(engine);
	return jcat_gnutls_pkcs7_engine_add_pubkey_blob_fmt(self, blob, GNUTLS_X509_FMT_PEM, error);
}

static gboolean
jcat_gnutls_pkcs7_engine_add_public_key(JcatEngine *engine, const gchar *filename, GError **error)
{
	JcatGnutlsPkcs7Engine *self = JCAT_GNUTLS_PKCS7_ENGINE(engine);

	/* search all the public key files */
	if (g_str_has_suffix(filename, ".pem")) {
		g_autoptr(GBytes) blob = jcat_get_contents_bytes(filename, error);
		if (blob == NULL)
			return FALSE;
		if (!jcat_gnutls_pkcs7_engine_add_pubkey_blob_fmt(self,
								  blob,
								  GNUTLS_X509_FMT_PEM,
								  error))
			return FALSE;
	} else if (g_str_has_suffix(filename, ".cer") || g_str_has_suffix(filename, ".crt") ||
		   g_str_has_suffix(filename, ".der")) {
		g_autoptr(GBytes) blob = jcat_get_contents_bytes(filename, error);
		if (blob == NULL)
			return FALSE;
		if (!jcat_gnutls_pkcs7_engine_add_pubkey_blob_fmt(self,
								  blob,
								  GNUTLS_X509_FMT_DER,
								  error))
			return FALSE;
	} else {
		g_autofree gchar *basename = g_path_get_basename(filename);
		g_debug("ignoring %s as not PKCS-7 certificate", basename);
	}
	return TRUE;
}

static gboolean
jcat_gnutls_pkcs7_engine_setup(JcatEngine *engine, GError **error)
{
	JcatGnutlsPkcs7Engine *self = JCAT_GNUTLS_PKCS7_ENGINE(engine);
	int rc;

	if (self->tl != NULL)
		return TRUE;

	/* create trust list, a bit like a engine */
	rc = gnutls_x509_trust_list_init(&self->tl, 0);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to create trust list: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return FALSE;
	}
	return TRUE;
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_gnutls_pkcs7_engine_verify(JcatEngine *engine,
				GBytes *blob,
				GBytes *blob_signature,
				gnutls_x509_crt_t crt,
				JcatVerifyFlags flags,
				GError **error)
{
	JcatGnutlsPkcs7Engine *self = JCAT_GNUTLS_PKCS7_ENGINE(engine);
	gnutls_datum_t datum = {0};
	gint64 timestamp_newest = 0;
	gnutls_pkcs7_signature_info_st info_tmp = {0x0};
	int count;
	int rc;
	g_auto(gnutls_pkcs7_t) pkcs7 = NULL;
	g_autoptr(GString) authority_newest = g_string_new(NULL);

	/* startup */
	rc = gnutls_pkcs7_init(&pkcs7);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to init pkcs7: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* import the signature */
	datum.data = (guchar *)g_bytes_get_data(blob_signature, NULL);
	datum.size = g_bytes_get_size(blob_signature);
	rc = gnutls_pkcs7_import(pkcs7, &datum, GNUTLS_X509_FMT_PEM);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to import the PKCS7 signature: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* verify the blob */
	datum.data = (guchar *)g_bytes_get_data(blob, NULL);
	datum.size = g_bytes_get_size(blob);
	count = gnutls_pkcs7_get_signature_count(pkcs7);
	g_debug("got %i PKCS7 signatures", count);
	if (count == 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "no PKCS7 signatures found");
		return NULL;
	}
	for (gint i = 0; i < count; i++) {
		g_autoptr(gnutls_pkcs7_signature_info_st) info = &info_tmp;
		gint64 signing_time = 0;
		gnutls_certificate_verify_flags verify_flags = 0;
		g_autofree gchar *dn = NULL;

		/* use with care */
		if (flags & JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS) {
			g_debug("WARNING: disabling time checks");
			verify_flags |= GNUTLS_VERIFY_DISABLE_TIME_CHECKS;
			verify_flags |= GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS;
		}

		/* always get issuer */
		rc = gnutls_pkcs7_get_signature_info(pkcs7, i, &info_tmp);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to get signature info: %s [%i]",
				    gnutls_strerror(rc),
				    rc);
			return NULL;
		}

		/* verify the data against the detached signature */
		if (crt != NULL) {
			rc = gnutls_pkcs7_verify_direct(pkcs7, crt, i, &datum, 0);
		} else {
			rc = gnutls_pkcs7_verify(pkcs7,
						 self->tl,
						 NULL,	 /* vdata */
						 0,	 /* vdata_size */
						 i,	 /* index */
						 &datum, /* data */
						 verify_flags);
		}
		if (rc < 0) {
			dn = jcat_gnutls_pkcs7_datum_to_dn_str(&info->issuer_dn);
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to verify data for %s: %s [%i]",
				    dn,
				    gnutls_strerror(rc),
				    rc);
			return NULL;
		}

		/* save details about the key for the result */
		signing_time = info->signing_time > 0 ? (gint64)info->signing_time : 1;
		if (signing_time > timestamp_newest) {
			timestamp_newest = signing_time;
			dn = jcat_gnutls_pkcs7_datum_to_dn_str(&info->issuer_dn);
			if (dn != NULL)
				g_string_assign(authority_newest, dn);
		}
	}

	/* success */
	return JCAT_RESULT(g_object_new(JCAT_TYPE_RESULT,
					"engine",
					engine,
					"timestamp",
					timestamp_newest,
					"authority",
					authority_newest->str,
					NULL));
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_gnutls_pkcs7_engine_self_verify(JcatEngine *engine,
				     GBytes *blob,
				     GBytes *blob_signature,
				     JcatVerifyFlags flags,
				     GError **error)
{
	g_autofree gchar *filename = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(GBytes) cert_blob = NULL;

	filename =
	    g_build_filename(jcat_engine_get_keyring_path(engine), "pki", "client.pem", NULL);
	cert_blob = jcat_get_contents_bytes(filename, error);
	if (cert_blob == NULL)
		return NULL;
	crt = jcat_gnutls_pkcs7_load_crt_from_blob(cert_blob, GNUTLS_X509_FMT_PEM, error);
	if (crt == NULL)
		return NULL;

	return jcat_gnutls_pkcs7_engine_verify(engine, blob, blob_signature, crt, flags, error);
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_gnutls_pkcs7_engine_pubkey_verify(JcatEngine *engine,
				       GBytes *blob,
				       GBytes *blob_signature,
				       JcatVerifyFlags flags,
				       GError **error)
{
	return jcat_gnutls_pkcs7_engine_verify(engine, blob, blob_signature, NULL, flags, error);
}

static JcatBlob *
jcat_gnutls_pkcs7_engine_pubkey_sign(JcatEngine *engine,
				     GBytes *blob,
				     GBytes *cert,
				     GBytes *privkey,
				     JcatSignFlags flags,
				     GError **error)
{
	gnutls_datum_t d = {0};
	gnutls_digest_algorithm_t dig = GNUTLS_DIG_NULL;
	guint gnutls_flags = 0;
	int rc;
	g_autofree gchar *str = NULL;
	g_auto(gnutls_pkcs7_t) pkcs7 = NULL;
	g_auto(gnutls_privkey_t) key = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* nothing to do */
	if (g_bytes_get_size(blob) == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "nothing to do");
		return NULL;
	}

	/* load keys */
	key = jcat_gnutls_pkcs7_load_privkey_from_blob(privkey, error);
	if (key == NULL)
		return NULL;
	crt = jcat_gnutls_pkcs7_load_crt_from_blob(cert, GNUTLS_X509_FMT_PEM, error);
	if (crt == NULL)
		return NULL;

	/* get the digest algorithm from the publix key */
	pubkey = jcat_gnutls_pkcs7_load_pubkey_from_privkey(key, error);
	if (pubkey == NULL)
		return NULL;
	rc = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig, NULL);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "preferred_hash_algorithm: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	g_debug("preferred_hash_algorithm=%s", gnutls_digest_get_name(dig));

	/* create container */
	rc = gnutls_pkcs7_init(&pkcs7);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pkcs7_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* sign data */
	d.data = (unsigned char *)g_bytes_get_data(blob, NULL);
	d.size = g_bytes_get_size(blob);
	if (flags & JCAT_SIGN_FLAG_ADD_TIMESTAMP)
		gnutls_flags |= GNUTLS_PKCS7_INCLUDE_TIME;
	if (flags & JCAT_SIGN_FLAG_ADD_CERT)
		gnutls_flags |= GNUTLS_PKCS7_INCLUDE_CERT;
	rc = gnutls_pkcs7_sign(pkcs7, crt, key, &d, NULL, NULL, dig, gnutls_flags);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pkcs7_sign: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set certificate */
	if (flags & JCAT_SIGN_FLAG_ADD_CERT) {
		rc = gnutls_pkcs7_set_crt(pkcs7, crt);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "pkcs7_set_cr: %s",
				    gnutls_strerror(rc));
			return NULL;
		}
	}

	/* export */
	rc = gnutls_pkcs7_export2(pkcs7, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pkcs7_export: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	d_payload = d.data;
	str = g_strndup((const gchar *)d_payload, d.size);
	return jcat_blob_new_utf8(JCAT_BLOB_KIND_PKCS7, str);
}

/* creates a detached signature just like:
 *  `certtool --p7-detached-sign --load-certificate client.pem \
 *    --load-privkey secret.pem --outfile=test.p7b` */
static JcatBlob *
jcat_gnutls_pkcs7_engine_self_sign(JcatEngine *engine,
				   GBytes *blob,
				   JcatSignFlags flags,
				   GError **error)
{
	g_autofree gchar *fn_cert = NULL;
	g_autofree gchar *fn_privkey = NULL;
	g_autoptr(GBytes) cert = NULL;
	g_autoptr(GBytes) privkey = NULL;

	/* check private key exists, otherwise generate and save */
	fn_privkey =
	    g_build_filename(jcat_engine_get_keyring_path(engine), "pki", "secret.key", NULL);
	if (g_file_test(fn_privkey, G_FILE_TEST_EXISTS)) {
		privkey = jcat_get_contents_bytes(fn_privkey, error);
		if (privkey == NULL)
			return NULL;
	} else {
		privkey = jcat_gnutls_pkcs7_create_private_key(GNUTLS_PK_RSA, error);
		if (privkey == NULL)
			return NULL;
		if (!jcat_mkdir_parent(fn_privkey, error))
			return NULL;
		if (!jcat_set_contents_bytes(fn_privkey, privkey, 0600, error))
			return NULL;
	}

	/* check client certificate exists, otherwise generate and save */
	fn_cert = g_build_filename(jcat_engine_get_keyring_path(engine), "pki", "client.pem", NULL);
	if (g_file_test(fn_cert, G_FILE_TEST_EXISTS)) {
		cert = jcat_get_contents_bytes(fn_cert, error);
		if (cert == NULL)
			return NULL;
	} else {
		g_auto(gnutls_privkey_t) key = NULL;
		key = jcat_gnutls_pkcs7_load_privkey_from_blob(privkey, error);
		if (key == NULL)
			return NULL;
		cert = jcat_gnutls_pkcs7_create_client_certificate(key, error);
		if (cert == NULL)
			return NULL;
		if (!jcat_mkdir_parent(fn_cert, error))
			return NULL;
		if (!jcat_set_contents_bytes(fn_cert, cert, 0666, error))
			return NULL;
	}

	/* sign */
	return jcat_gnutls_pkcs7_engine_pubkey_sign(engine, blob, cert, privkey, flags, error);
}

static void
jcat_gnutls_pkcs7_engine_finalize(GObject *object)
{
	JcatGnutlsPkcs7Engine *self = JCAT_GNUTLS_PKCS7_ENGINE(object);
	gnutls_x509_trust_list_deinit(self->tl, 1);
	G_OBJECT_CLASS(jcat_gnutls_pkcs7_engine_parent_class)->finalize(object);
}

static void
jcat_gnutls_pkcs7_engine_class_init(JcatGnutlsPkcs7EngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	JcatEngineClass *engine_class = JCAT_ENGINE_CLASS(klass);
	engine_class->setup = jcat_gnutls_pkcs7_engine_setup;
	engine_class->add_public_key = jcat_gnutls_pkcs7_engine_add_public_key;
	engine_class->add_public_key_raw = jcat_gnutls_pkcs7_engine_add_public_key_raw;
	engine_class->pubkey_verify = jcat_gnutls_pkcs7_engine_pubkey_verify;
	engine_class->pubkey_sign = jcat_gnutls_pkcs7_engine_pubkey_sign;
	engine_class->self_verify = jcat_gnutls_pkcs7_engine_self_verify;
	engine_class->self_sign = jcat_gnutls_pkcs7_engine_self_sign;
	object_class->finalize = jcat_gnutls_pkcs7_engine_finalize;
}

static void
jcat_gnutls_pkcs7_engine_init(JcatGnutlsPkcs7Engine *self)
{
}

JcatEngine *
jcat_gnutls_pkcs7_engine_new(JcatContext *context)
{
	g_return_val_if_fail(JCAT_IS_CONTEXT(context), NULL);
	return JCAT_ENGINE(g_object_new(JCAT_TYPE_GNUTLS_PKCS7_ENGINE,
					"context",
					context,
					"kind",
					JCAT_BLOB_KIND_PKCS7,
					"method",
					JCAT_BLOB_METHOD_SIGNATURE,
					NULL));
}
