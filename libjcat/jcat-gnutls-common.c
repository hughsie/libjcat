/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-gnutls-common.h"

gboolean
jcat_gnutls_ensure_trust_list_valid(gnutls_x509_trust_list_t tl, GError **error)
{
	guint cnt = 0;
	g_auto(gnutls_x509_trust_list_iter_t) iter = NULL;

	/* check we have more than zero certs */
	while (1) {
		int rc;
		g_auto(gnutls_x509_crt_t) cert = NULL;

		rc = gnutls_x509_trust_list_iter_get_ca(tl, &iter, &cert);
		if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (rc != GNUTLS_E_SUCCESS) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to get ca from trust list: %s [%i]",
				    gnutls_strerror(rc),
				    rc);
			return FALSE;
		}
		cnt++;
	}
	if (cnt == 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "no certificates in trust list");
		return FALSE;
	}

	/* success */
	return TRUE;
}

gnutls_x509_crt_t
jcat_gnutls_pkcs7_load_crt_from_blob(GBytes *blob, gnutls_x509_crt_fmt_t format, GError **error)
{
	gnutls_datum_t d = {0};
	int rc;
	g_auto(gnutls_x509_crt_t) crt = NULL;

	/* create certificate */
	rc = gnutls_x509_crt_init(&crt);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* import the certificate */
	d.size = g_bytes_get_size(blob);
	d.data = (unsigned char *)g_bytes_get_data(blob, NULL);
	rc = gnutls_x509_crt_import(crt, &d, format);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_import: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	return g_steal_pointer(&crt);
}

gnutls_privkey_t
jcat_gnutls_pkcs7_load_privkey_from_blob(GBytes *blob, GError **error)
{
	int rc;
	gnutls_datum_t d = {0};
	g_auto(gnutls_privkey_t) key = NULL;

	/* load the private key */
	rc = gnutls_privkey_init(&key);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	d.size = g_bytes_get_size(blob);
	d.data = (unsigned char *)g_bytes_get_data(blob, NULL);
	rc = gnutls_privkey_import_x509_raw(key, &d, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_import_x509_raw: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	return g_steal_pointer(&key);
}

gnutls_pubkey_t
jcat_gnutls_pkcs7_load_pubkey_from_privkey(gnutls_privkey_t privkey, GError **error)
{
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	int rc;

	/* get the public key part of the private key */
	rc = gnutls_pubkey_init(&pubkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pubkey_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	rc = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pubkey_import_privkey: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* success */
	return g_steal_pointer(&pubkey);
}

gchar *
jcat_gnutls_pkcs7_datum_to_dn_str(const gnutls_datum_t *raw)
{
	g_auto(gnutls_x509_dn_t) dn = NULL;
	g_autoptr(gnutls_datum_t) str = NULL;
	int rc;
	rc = gnutls_x509_dn_init(&dn);
	if (rc < 0)
		return NULL;
	rc = gnutls_x509_dn_import(dn, raw);
	if (rc < 0)
		return NULL;
	str = (gnutls_datum_t *)gnutls_malloc(sizeof(gnutls_datum_t));
	str->data = NULL;
	rc = gnutls_x509_dn_get_str2(dn, str, 0);
	if (rc < 0)
		return NULL;
	return g_strndup((const gchar *)str->data, str->size);
}

/* generates a private key just like `certtool --generate-privkey` */
GBytes *
jcat_gnutls_pkcs7_create_private_key(gnutls_pk_algorithm_t algo, GError **error)
{
	gnutls_datum_t d = {0};
	int bits;
	int rc;
	g_auto(gnutls_x509_privkey_t) key = NULL;
	g_auto(gnutls_x509_spki_t) spki = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* initialize key and SPKI */
	rc = gnutls_x509_privkey_init(&key);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	rc = gnutls_x509_spki_init(&spki);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "spki_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* generate key */
	bits = gnutls_sec_param_to_pk_bits(algo, GNUTLS_SEC_PARAM_HIGH);
	g_debug("generating a %d bit %s private key...", bits, gnutls_pk_algorithm_get_name(algo));
	rc = gnutls_x509_privkey_generate2(key, algo, bits, 0, NULL, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_generate2: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	rc = gnutls_x509_privkey_verify_params(key);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_verify_params: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* save to file */
	rc = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "privkey_export2: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	d_payload = d.data;
	return g_bytes_new(d_payload, d.size);
}

gboolean
jcat_gnutls_pkcs7_ensure_sign_algo_pq_safe(gnutls_sign_algorithm_t algo, GError **error)
{
#ifdef HAVE_GNUTLS_PQC
	if (algo == GNUTLS_SIGN_MLDSA44 || algo == GNUTLS_SIGN_MLDSA65 ||
	    algo == GNUTLS_SIGN_MLDSA87)
		return TRUE;
	g_set_error(error,
		    G_IO_ERROR,
		    G_IO_ERROR_INVALID_DATA,
		    "%s is not PQ safe",
		    gnutls_sign_get_name(algo));
	return FALSE;
#else
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "GnuTLS too old for PQC support");
	return FALSE;
#endif
}

/* generates a self signed certificate just like:
 *  `certtool --generate-self-signed --load-privkey priv.pem` */
GBytes *
jcat_gnutls_pkcs7_create_client_certificate(gnutls_privkey_t privkey, GError **error)
{
	int rc;
	gnutls_datum_t d = {0};
	guchar sha1buf[20];
	gsize sha1bufsz = sizeof(sha1buf);
	gnutls_digest_algorithm_t digest_alg = GNUTLS_DIG_NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_x509_crt_t) crt = NULL;
	g_autoptr(gnutls_data_t) d_payload = NULL;

	/* load the public key from the private key */
	pubkey = jcat_gnutls_pkcs7_load_pubkey_from_privkey(privkey, error);
	if (pubkey == NULL)
		return NULL;

	rc = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &digest_alg, NULL);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "preferred_hash_algorithm: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	g_debug("preferred_hash_algorithm=%s", gnutls_digest_get_name(digest_alg));

	/* create certificate */
	rc = gnutls_x509_crt_init(&crt);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_init: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set public key */
	rc = gnutls_x509_crt_set_pubkey(crt, pubkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_set_pubkey: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set positive random serial number */
	rc = gnutls_rnd(GNUTLS_RND_NONCE, sha1buf, sizeof(sha1buf));
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "gnutls_rnd: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	sha1buf[0] &= 0x7f;
	rc = gnutls_x509_crt_set_serial(crt, sha1buf, sizeof(sha1buf));
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_set_serial: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set activation */
	rc = gnutls_x509_crt_set_activation_time(crt, time(NULL));
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "set_activation_time: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set expiration */
	rc = gnutls_x509_crt_set_expiration_time(crt, (time_t)-1);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "set_expiration_time: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set basic constraints */
	rc = gnutls_x509_crt_set_basic_constraints(crt, 0, -1);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "set_basic_constraints: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set usage */
	rc = gnutls_x509_crt_set_key_usage(crt, GNUTLS_KEY_DIGITAL_SIGNATURE);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "set_key_usage: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set subject key ID */
	rc = gnutls_x509_crt_get_key_id(crt, GNUTLS_KEYID_USE_SHA1, sha1buf, &sha1bufsz);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "get_key_id: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	rc = gnutls_x509_crt_set_subject_key_id(crt, sha1buf, sha1bufsz);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "set_subject_key_id: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* set version */
	rc = gnutls_x509_crt_set_version(crt, 3);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "error setting certificate version: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* self-sign certificate */
	rc = gnutls_x509_crt_privkey_sign(crt, crt, privkey, digest_alg, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_privkey_sign: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}

	/* export to file */
	rc = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &d);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "crt_export2: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return NULL;
	}
	d_payload = d.data;
	return g_bytes_new(d_payload, d.size);
}

static void
jcat_gnutls_global_log_cb(int level, const char *msg)
{
	g_auto(GStrv) lines = g_strsplit(msg, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		if (lines[i][0] == '\0')
			continue;
		g_debug("GnuTLS: %s", lines[i]);
	}
}

void
jcat_gnutls_global_init(void)
{
	gnutls_global_set_log_level(3);
	gnutls_global_set_log_function(jcat_gnutls_global_log_cb);
}
