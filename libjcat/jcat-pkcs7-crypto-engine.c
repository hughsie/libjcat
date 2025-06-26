/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2025 Colin Kinloch <colin.kinloch@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-engine-private.h"
#include "jcat-pkcs7-crypto-common.h"
#include "jcat-pkcs7-crypto-engine.h"

struct _JcatPkcs7Engine {
	JcatEngine parent_instance;
	X509_STORE *trust_store;
};

G_DEFINE_TYPE(JcatPkcs7Engine, jcat_pkcs7_engine, JCAT_TYPE_ENGINE)


static gboolean
jcat_pkcs7_engine_add_pubkey_x509(JcatPkcs7Engine *self,
				      X509 *crt,
				      GError **error)
{
	guint32 key_usage = X509_get_key_usage(crt);

	if ((key_usage & X509v3_KU_DIGITAL_SIGNATURE) == 0 &&
		(key_usage & X509v3_KU_KEY_CERT_SIGN) == 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "certificate not suitable for use [0x%x]",
			    key_usage);
		return FALSE;
	}

	if (!X509_STORE_add_cert(self->trust_store, crt)) {
		g_autofree gchar *error_str = jcat_pkcs7_get_errors();

		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed add x509 certificate to the trust store: %s",
			    error_str);
		return FALSE;
	}

	return TRUE;
}

static gboolean
jcat_pkcs7_engine_add_public_key_raw(JcatEngine *engine, GBytes *blob, GError **error)
{
	JcatPkcs7Engine *self = JCAT_PKCS7_ENGINE(engine);
	g_autoptr(X509) cert = jcat_pkcs7_load_crt_from_blob_pem(blob, error);
	if (cert == NULL) {
		return FALSE;
	}

	return jcat_pkcs7_engine_add_pubkey_x509(self, cert, error);
}

static gboolean
jcat_pkcs7_engine_add_public_key(JcatEngine *engine, const gchar *filename, GError **error)
{
	JcatPkcs7Engine *self = JCAT_PKCS7_ENGINE(engine);
	g_autoptr(X509) crt = NULL;

	/* search all the public key files */
	if (g_str_has_suffix(filename, ".pem")) {
		g_autoptr(GBytes) blob = jcat_get_contents_bytes(filename, error);
		if (blob == NULL)
			return FALSE;
		crt = jcat_pkcs7_load_crt_from_blob_pem(blob, error);
		if (crt == NULL) {
			return FALSE;
		}
		if (!jcat_pkcs7_engine_add_pubkey_x509(self, crt, error)) {
			return FALSE;
		}
	} else if (g_str_has_suffix(filename, ".cer") || g_str_has_suffix(filename, ".crt") ||
		   g_str_has_suffix(filename, ".der")) {
		g_autoptr(GBytes) blob = jcat_get_contents_bytes(filename, error);
		if (blob == NULL)
			return FALSE;
		crt = jcat_pkcs7_load_crt_from_blob_der(blob, error);
		if (crt == NULL) {
			return FALSE;
		}
		if (!jcat_pkcs7_engine_add_pubkey_x509(self, crt, error)) {
			return FALSE;
		}
	} else {
		g_autofree gchar *basename = g_path_get_basename(filename);
		g_debug("ignoring %s as not PKCS-7 certificate", basename);
	}

	return TRUE;
}

static gboolean
jcat_pkcs7_engine_setup(JcatEngine *engine, GError **error)
{
	JcatPkcs7Engine *self = JCAT_PKCS7_ENGINE(engine);

	if (self->trust_store != NULL)
		return TRUE;

	self->trust_store = X509_STORE_new();

	if (self->trust_store == NULL) {
		g_autofree gchar *error_str = jcat_pkcs7_get_errors();

		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to create x509 store: %s",
			    error_str);
		return FALSE;
	}

	return TRUE;
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_pkcs7_engine_verify(JcatEngine *engine,
			 GBytes *blob,
			 GBytes *blob_signature,
			 X509 *crt,
			 JcatVerifyFlags flags,
			 GError **error)
{
	JcatPkcs7Engine *self = JCAT_PKCS7_ENGINE(engine);
	g_autoptr(CMS_ContentInfo) cms = NULL;
	STACK_OF(CMS_SignerInfo) *infos = NULL;
	gsize blob_size = 0;
	gsize sig_size = 0;
	int rc;
	int verify_flags = CMS_BINARY;
	g_autoptr(BIO) bio = NULL;
	g_autoptr(BIO) bio_signature = NULL;
	gint64 timestamp_newest = 0;
	g_autoptr(GString) authority_newest = g_string_new(NULL);
	g_autoptr(OSSL_DECODER_CTX) dctx = OSSL_DECODER_CTX_new();

	/* import the signature */
	sig_size = g_bytes_get_size(blob_signature);
	bio_signature = BIO_new_mem_buf(g_bytes_get_data(blob_signature, NULL), sig_size);
	cms = PEM_read_bio_CMS(bio_signature, &cms, NULL, NULL);
	if (cms == NULL) {
		g_autofree gchar *error_str = jcat_pkcs7_get_errors();
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to parse pkcs7 pem: %s",
			    error_str);
		return NULL;
	}

	/* configure trust store for verification */
	{
		X509_VERIFY_PARAM *param = X509_STORE_get0_param(self->trust_store);
		/* without setting this the LVFS-CA.pem can't be used to for verify CMS */
		X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY);

		/* use with care */
		if (flags & JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS) {
			g_debug("WARNING: disabling time checks");
			X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
		} else {
			X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NO_CHECK_TIME);
		}
	}

	/* verify the blob */
	blob_size = g_bytes_get_size(blob);
	bio = BIO_new_mem_buf(g_bytes_get_data(blob, NULL), blob_size);
	if (crt != NULL) {
		g_autoptr(STACK_OF_X509) signer_certs = sk_X509_new_null();
		sk_X509_push(signer_certs, crt);

		// TODO: Make sure that this actually verifys what we want to verify
		/* setting this based on CMS_NOCERTS in pubkey_sign. Maybe redundant with CMS_NO_SIGNER_CERT_VERIFY */
		verify_flags |= CMS_NOINTERN;
		/* setting this to allow self signed certs */
		verify_flags |= CMS_NO_SIGNER_CERT_VERIFY;
		rc = CMS_verify(cms, signer_certs, NULL, bio, NULL, verify_flags);
	} else {
		rc = CMS_verify(cms, NULL, self->trust_store, bio, NULL, verify_flags);
	}

	if (rc <= 0) {
		g_autofree gchar *error_str = jcat_pkcs7_get_errors();
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "pkcs7 verification failed: %s",
			    error_str);
		return NULL;
	}

	/* save details about the key for the result */
	infos = CMS_get0_SignerInfos(cms);
	for (int i = 0; i < sk_CMS_SignerInfo_num(infos); i++)
	{
		CMS_SignerInfo *info = sk_CMS_SignerInfo_value(infos, i);
		g_autoptr(BIO) time_bio = NULL;
		struct tm time_tm;
		time_t signing_time;
		int stime_loc = CMS_signed_get_attr_by_NID(info, NID_pkcs9_signingTime, -1);
		X509_ATTRIBUTE* stime_attr = CMS_signed_get_attr(info, stime_loc);
		ASN1_TYPE* stime = X509_ATTRIBUTE_get0_type(stime_attr, 0);
		ASN1_TIME *t = NULL;
		if (stime && (stime->type == V_ASN1_UTCTIME || stime->type == V_ASN1_GENERALIZEDTIME)) {
			t = (ASN1_TIME*) stime->value.asn1_value;
		} else {
				g_autofree gchar *error_str = jcat_pkcs7_get_errors();
				g_set_error(error,
						G_IO_ERROR,
						G_IO_ERROR_INVALID_DATA,
						"failed to extract timestamp: %s",
						error_str);
			return NULL;
		}

		if (!ASN1_TIME_to_tm(t, &time_tm)) {
				g_autofree gchar *error_str = jcat_pkcs7_get_errors();
				g_set_error(error,
						G_IO_ERROR,
						G_IO_ERROR_INVALID_DATA,
						"failed to convert timestamp: %s",
						error_str);
			return NULL;
		}

		signing_time = mktime(&time_tm);

		if (signing_time > timestamp_newest) {
			g_autoptr(BIO) issuer_bio = BIO_new(BIO_s_mem());
			X509_NAME *issuer_name = NULL;
			gchar *issuer_string = NULL;
			gsize issuer_size;

			timestamp_newest = signing_time;

			if (!CMS_SignerInfo_get0_signer_id(info, NULL, &issuer_name, NULL)) {
				g_autofree gchar *error_str = jcat_pkcs7_get_errors();
				g_set_error(error,
					G_IO_ERROR,
					G_IO_ERROR_INVALID_DATA,
					"failed to get CMS signer id: %s",
					error_str);
				return NULL;
			}

			if (X509_NAME_print_ex(issuer_bio, issuer_name, 0, XN_FLAG_RFC2253) == -1) {
				g_autofree gchar *error_str = jcat_pkcs7_get_errors();
				g_set_error(error,
					G_IO_ERROR,
					G_IO_ERROR_INVALID_DATA,
					"failed to parse certificate issuer a: %s",
					error_str);
				return NULL;
			}

			issuer_size = BIO_get_mem_data(issuer_bio, &issuer_string);
			g_strndup(issuer_string, issuer_size);

			if (issuer_size > 0 && issuer_string != NULL) {
				/* issuer name isn't null terminated */
				g_string_overwrite_len(authority_newest, 0, issuer_string, issuer_size);
				g_string_truncate(authority_newest, issuer_size);
			}
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
jcat_pkcs7_engine_self_verify(JcatEngine *engine,
			      GBytes *blob,
			      GBytes *blob_signature,
			      JcatVerifyFlags flags,
			      GError **error)
{
	g_autofree gchar *filename = NULL;
	g_autoptr(X509) crt = NULL;
	g_autoptr(GBytes) cert_blob = NULL;

	filename =
	    g_build_filename(jcat_engine_get_keyring_path(engine), "pki", "client.pem", NULL);
	cert_blob = jcat_get_contents_bytes(filename, error);
	if (cert_blob == NULL)
		return NULL;
	crt = jcat_pkcs7_load_crt_from_blob_pem(cert_blob, error);
	if (crt == NULL)
		return NULL;

	return jcat_pkcs7_engine_verify(engine, blob, blob_signature, crt, flags, error);
}

/* verifies a detached signature just like:
 *  `certtool --p7-verify --load-certificate client.pem --infile=test.p7b` */
static JcatResult *
jcat_pkcs7_engine_pubkey_verify(JcatEngine *engine,
				GBytes *blob,
				GBytes *blob_signature,
				JcatVerifyFlags flags,
				GError **error)
{
	return jcat_pkcs7_engine_verify(engine, blob, blob_signature, NULL, flags, error);
}

static JcatBlob *
jcat_pkcs7_engine_pubkey_sign(JcatEngine *engine,
			      GBytes *blob,
			      GBytes *cert,
			      GBytes *privkey,
			      JcatSignFlags flags,
			      GError **error)
{
	g_autoptr(EVP_PKEY) key = NULL;
	g_autoptr(X509) crt = NULL;
	guint signing_flags = CMS_DETACHED;

	/* nothing to do */
	if (g_bytes_get_size(blob) == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "nothing to do");
		return NULL;
	}

	/* load keys */
	key = jcat_pkcs7_load_privkey_from_blob_pem(privkey, error);
	if (key == NULL)
		return NULL;
	crt = jcat_pkcs7_load_crt_from_blob_pem(cert, error);
	if (crt == NULL)
		return NULL;


	/* get the digest algorithm from the public key */
	// TODO: The gnutls uses the keys "preferred_hash_algorithm". Port that if necissary.
	// gchar mdname[256] = {0};
	// gint default_digest_nid = 0;
	// EVP_PKEY_get_default_digest_name(key, mdname, sizeof(mdname));
	// EVP_PKEY_get_default_digest_nid(key, &default_digest_nid);
	// g_debug("pubkey_sign pref digest %s %d", mdname, default_digest_nid);

	/* sign data */
	// TODO: Implement these sign ing flags
	// TODO: CMS_NO_SIGNING_TIME was added in OpenSSL 3.5
	//if (!(flags & JCAT_SIGN_FLAG_ADD_TIMESTAMP))
	//	signing_flags |= CMS_NO_SIGNING_TIME;
	if (!(flags & JCAT_SIGN_FLAG_ADD_CERT))
		signing_flags |= CMS_NOCERTS;
	g_autoptr(BIO) blob_bio = BIO_new_mem_buf(g_bytes_get_data(blob, NULL), g_bytes_get_size(blob));
	g_autoptr(CMS_ContentInfo) cms_ci = CMS_sign(crt, key, NULL, blob_bio, signing_flags);

	g_autoptr(BIO) sig_bio = BIO_new(BIO_s_mem());

	if (!PEM_write_bio_CMS(sig_bio, cms_ci)) {
		g_autofree gchar *error_str = jcat_pkcs7_get_errors();
		g_set_error(error,
			G_IO_ERROR,
			G_IO_ERROR_INVALID_DATA,
			"failed to encode pkcs7 as pem: %s",
			error_str);
		return NULL;
	}

	gchar* bio_buf;
	gsize bio_len = BIO_get_mem_data(sig_bio, &bio_buf);
	gchar *str = g_strndup((const gchar *)bio_buf, bio_len);

	return jcat_blob_new_utf8(JCAT_BLOB_KIND_PKCS7, str);
}

/* creates a detached signature just like:
 *  `certtool --p7-detached-sign --load-certificate client.pem \
 *    --load-privkey secret.pem --outfile=test.p7b` */
static JcatBlob *
jcat_pkcs7_engine_self_sign(JcatEngine *engine, GBytes *blob, JcatSignFlags flags, GError **error)
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
		privkey = jcat_pkcs7_create_private_key(error);
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
		g_autoptr(EVP_PKEY) key = NULL;
		key = jcat_pkcs7_load_privkey_from_blob_pem(privkey, error);
		if (key == NULL)
			return NULL;
		cert = jcat_pkcs7_create_client_certificate(key, error);
		if (cert == NULL)
			return NULL;
		if (!jcat_mkdir_parent(fn_cert, error))
			return NULL;
		if (!jcat_set_contents_bytes(fn_cert, cert, 0666, error))
			return NULL;
	}

	/* sign */
	return jcat_pkcs7_engine_pubkey_sign(engine, blob, cert, privkey, flags, error);
}

static void
jcat_pkcs7_engine_finalize(GObject *object)
{
	JcatPkcs7Engine *self = JCAT_PKCS7_ENGINE(object);

	X509_STORE_free(self->trust_store);

	G_OBJECT_CLASS(jcat_pkcs7_engine_parent_class)->finalize(object);
}

static void
jcat_pkcs7_engine_class_init(JcatPkcs7EngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS(klass);
	klass_app->setup = jcat_pkcs7_engine_setup;
	klass_app->add_public_key = jcat_pkcs7_engine_add_public_key;
	klass_app->add_public_key_raw = jcat_pkcs7_engine_add_public_key_raw;
	klass_app->pubkey_verify = jcat_pkcs7_engine_pubkey_verify;
	klass_app->pubkey_sign = jcat_pkcs7_engine_pubkey_sign;
	klass_app->self_verify = jcat_pkcs7_engine_self_verify;
	klass_app->self_sign = jcat_pkcs7_engine_self_sign;
	object_class->finalize = jcat_pkcs7_engine_finalize;
}

static void
jcat_pkcs7_engine_init(JcatPkcs7Engine *self)
{
}

JcatEngine *
jcat_pkcs7_engine_new(JcatContext *context)
{
	g_return_val_if_fail(JCAT_IS_CONTEXT(context), NULL);
	return JCAT_ENGINE(g_object_new(JCAT_TYPE_PKCS7_ENGINE,
					"context",
					context,
					"kind",
					JCAT_BLOB_KIND_PKCS7,
					"method",
					JCAT_BLOB_METHOD_SIGNATURE,
					NULL));
}
