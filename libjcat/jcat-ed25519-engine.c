/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include "jcat-common-private.h"
#include "jcat-ed25519-engine.h"
#include "jcat-engine-private.h"

struct _JcatEd25519Engine {
	JcatEngine parent_instance;
	GPtrArray *pubkeys; /* of gnutls_pubkey_t */
};

G_DEFINE_TYPE(JcatEd25519Engine, jcat_ed25519_engine, JCAT_TYPE_ENGINE)

static void
jcat_ed25519_datum_clear(gnutls_datum_t *data)
{
	gnutls_free(data->data);
}

G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_pubkey_t, gnutls_pubkey_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_privkey_t, gnutls_privkey_deinit, NULL)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(gnutls_datum_t, jcat_ed25519_datum_clear)

static GBytes *
jcat_ed25519_pubkey_to_bytes(const gnutls_pubkey_t pubkey, GError **error)
{
	gint rc;
	g_auto(gnutls_datum_t) x = {NULL, 0};

	rc = gnutls_pubkey_export_ecc_raw(pubkey, NULL, &x, NULL);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to export pubkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	return g_bytes_new(x.data, x.size);
}

static gboolean
jcat_ed25519_pubkey_from_bytes(GBytes *blob, gnutls_pubkey_t pubkey, GError **error)
{
	gint rc;
	gnutls_datum_t x = {NULL, 0};

	x.data = g_bytes_get_data(blob, NULL);
	x.size = g_bytes_get_size(blob);

	rc = gnutls_pubkey_import_ecc_raw(pubkey, GNUTLS_ECC_CURVE_ED25519, &x, NULL);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to import pubkey: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}

	return TRUE;
}

static GBytes *
jcat_ed25519_privkey_to_bytes(const gnutls_privkey_t privkey, GError **error)
{
	gint rc;
	g_auto(gnutls_datum_t) k = {NULL, 0};

	rc = gnutls_privkey_export_ecc_raw2(privkey, NULL, NULL, NULL, &k, 0);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to export pubkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	return g_bytes_new(k.data, k.size);
}

static gboolean
jcat_ed25519_privkey_from_bytes(GBytes *blob_public,
				GBytes *blob_privkey,
				gnutls_privkey_t privkey,
				GError **error)
{
	gint rc;
	gnutls_datum_t x = {NULL, 0};
	gnutls_datum_t k = {NULL, 0};

	x.data = g_bytes_get_data(blob_public, NULL);
	x.size = g_bytes_get_size(blob_public);

	k.data = g_bytes_get_data(blob_privkey, NULL);
	k.size = g_bytes_get_size(blob_privkey);

	rc = gnutls_privkey_import_ecc_raw(privkey, GNUTLS_ECC_CURVE_ED25519, &x, NULL, &k);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to import privkey: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}

	return TRUE;
}

static gboolean
jcat_ed25519_engine_add_public_key_raw(JcatEngine *engine, GBytes *blob, GError **error)
{
	JcatEd25519Engine *self = JCAT_ED25519_ENGINE(engine);
	gint rc;
	g_auto(gnutls_pubkey_t) pubkey = NULL;

	rc = gnutls_pubkey_init(&pubkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to allocate pubkey: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}

	if (!jcat_ed25519_pubkey_from_bytes(blob, pubkey, error))
		return FALSE;

	g_ptr_array_add(self->pubkeys, g_steal_pointer(&pubkey));
	return TRUE;
}

static gboolean
jcat_ed25519_engine_add_public_key(JcatEngine *engine, const gchar *filename, GError **error)
{
	g_autoptr(GBytes) blob = NULL;

	/* ignore */
	if (!g_str_has_suffix(filename, ".ed25519"))
		return TRUE;

	blob = jcat_get_contents_bytes(filename, error);
	if (blob == NULL)
		return FALSE;
	return jcat_ed25519_engine_add_public_key_raw(engine, blob, error);
}

static JcatResult *
jcat_ed25519_engine_pubkey_verify(JcatEngine *engine,
				  GBytes *blob,
				  GBytes *blob_signature,
				  JcatVerifyFlags flags,
				  GError **error)
{
	JcatEd25519Engine *self = JCAT_ED25519_ENGINE(engine);

	/* sanity check */
	if (self->pubkeys->len == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "no keys in keyring");
		return NULL;
	}

	/* verifies against any of the public keys */
	for (guint i = 0; i < self->pubkeys->len; i++) {
		gint rc;
		gnutls_pubkey_t pubkey = g_ptr_array_index(self->pubkeys, i);
		gnutls_datum_t data = {NULL, 0};
		gnutls_datum_t sig = {NULL, 0};

		data.data = g_bytes_get_data(blob, NULL);
		data.size = g_bytes_get_size(blob);
		sig.data = g_bytes_get_data(blob_signature, NULL);
		sig.size = g_bytes_get_size(blob_signature);
		rc = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_EDDSA_ED25519, 0, &data, &sig);
		if (rc == GNUTLS_E_SUCCESS)
			return JCAT_RESULT(g_object_new(JCAT_TYPE_RESULT, "engine", engine, NULL));
	}

	/* nothing found */
	g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "failed to verify data");
	return NULL;
}

static JcatBlob *
jcat_ed25519_engine_pubkey_sign(JcatEngine *engine,
				GBytes *blob,
				GBytes *blob_cert,
				GBytes *blob_privkey,
				JcatSignFlags flags,
				GError **error)
{
	gint rc;
	gnutls_datum_t data = {NULL, 0};
	g_autoptr(GBytes) blob_sig = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_privkey_t) privkey = NULL;
	g_auto(gnutls_datum_t) sig = {NULL, 0};

	/* nothing to do */
	if (g_bytes_get_size(blob) == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "nothing to do");
		return NULL;
	}

	/* load */
	rc = gnutls_privkey_init(&privkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to allocate privkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	if (!jcat_ed25519_privkey_from_bytes(blob_cert, blob_privkey, privkey, error))
		return NULL;

	/* sign */
	data.data = g_bytes_get_data(blob, NULL);
	data.size = g_bytes_get_size(blob);
	rc = gnutls_privkey_sign_data2(privkey, GNUTLS_SIGN_EDDSA_ED25519, 0, &data, &sig);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to sign data: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	blob_sig = g_bytes_new(sig.data, sig.size);
	return jcat_blob_new(JCAT_BLOB_KIND_ED25519, blob_sig);
}

static JcatResult *
jcat_ed25519_engine_self_verify(JcatEngine *engine,
				GBytes *blob,
				GBytes *blob_signature,
				JcatVerifyFlags flags,
				GError **error)
{
	gint rc;
	gnutls_datum_t data = {NULL, 0};
	gnutls_datum_t sig = {NULL, 0};
	const gchar *keyring_path = jcat_engine_get_keyring_path(engine);
	g_autofree gchar *fn_pubkey = NULL;
	g_autoptr(GBytes) blob_pubkey = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;

	fn_pubkey = g_build_filename(keyring_path, "pki", "public.ed25519", NULL);
	blob_pubkey = jcat_get_contents_bytes(fn_pubkey, error);
	if (blob_pubkey == NULL)
		return NULL;
	rc = gnutls_pubkey_init(&pubkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to allocate pubkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	if (!jcat_ed25519_pubkey_from_bytes(blob_pubkey, pubkey, error))
		return NULL;

	data.data = g_bytes_get_data(blob, NULL);
	data.size = g_bytes_get_size(blob);
	sig.data = g_bytes_get_data(blob_signature, NULL);
	sig.size = g_bytes_get_size(blob_signature);
	rc = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_EDDSA_ED25519, 0, &data, &sig);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to verify data: %s",
			    gnutls_strerror(rc));
		return NULL;
	}

	/* success */
	return JCAT_RESULT(g_object_new(JCAT_TYPE_RESULT, "engine", engine, NULL));
}

static JcatBlob *
jcat_ed25519_engine_self_sign(JcatEngine *engine, GBytes *blob, JcatSignFlags flags, GError **error)
{
	gint rc;
	gnutls_datum_t data = {NULL, 0};
	const gchar *keyring_path = jcat_engine_get_keyring_path(engine);
	g_autofree gchar *fn_privkey = NULL;
	g_autofree gchar *fn_pubkey = NULL;
	g_autoptr(GBytes) blob_privkey = NULL;
	g_autoptr(GBytes) blob_pubkey = NULL;
	g_auto(gnutls_pubkey_t) pubkey = NULL;
	g_auto(gnutls_privkey_t) privkey = NULL;
	g_autoptr(GBytes) blob_sig = NULL;
	g_auto(gnutls_datum_t) sig = {NULL, 0};

	rc = gnutls_privkey_init(&privkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to allocate privkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}

	rc = gnutls_pubkey_init(&pubkey);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to allocate pubkey: %s",
			    gnutls_strerror(rc));
		return NULL;
	}

	/* check keypair exists, otherwise generate and save */
	fn_privkey = g_build_filename(keyring_path, "pki", "secret.ed25519", NULL);
	fn_pubkey = g_build_filename(keyring_path, "pki", "public.ed25519", NULL);
	if (!g_file_test(fn_privkey, G_FILE_TEST_EXISTS)) {
		rc = gnutls_privkey_generate2(privkey, GNUTLS_PK_EDDSA_ED25519, 0, 0, NULL, 0);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to generate private key: %s [%i]",
				    gnutls_strerror(rc),
				    rc);
			return NULL;
		}
		rc = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "unable to import pubkey from privkey: %s",
				    gnutls_strerror(rc));
			return NULL;
		}
		if (!jcat_mkdir_parent(fn_privkey, error))
			return NULL;
		blob_pubkey = jcat_ed25519_pubkey_to_bytes(pubkey, error);
		if (!blob_pubkey)
			return NULL;
		if (!jcat_set_contents_bytes(fn_pubkey, blob_pubkey, 0666, error))
			return NULL;
		blob_privkey = jcat_ed25519_privkey_to_bytes(privkey, error);
		if (!blob_privkey)
			return NULL;
		if (!jcat_set_contents_bytes(fn_privkey, blob_privkey, 0600, error))
			return NULL;
	} else {
		blob_pubkey = jcat_get_contents_bytes(fn_pubkey, error);
		if (blob_pubkey == NULL)
			return NULL;
		if (!jcat_ed25519_pubkey_from_bytes(blob_pubkey, pubkey, error))
			return NULL;
		blob_privkey = jcat_get_contents_bytes(fn_privkey, error);
		if (blob_privkey == NULL)
			return NULL;
		if (!jcat_ed25519_privkey_from_bytes(blob_pubkey, blob_privkey, privkey, error))
			return NULL;
	}

	data.data = g_bytes_get_data(blob, NULL);
	data.size = g_bytes_get_size(blob);
	rc = gnutls_privkey_sign_data2(privkey, GNUTLS_SIGN_EDDSA_ED25519, 0, &data, &sig);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unable to sign data: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	blob_sig = g_bytes_new(sig.data, sig.size);
	return jcat_blob_new(JCAT_BLOB_KIND_ED25519, blob_sig);
}

static void
jcat_ed25519_engine_finalize(GObject *object)
{
	JcatEd25519Engine *self = JCAT_ED25519_ENGINE(object);
	g_ptr_array_unref(self->pubkeys);
	G_OBJECT_CLASS(jcat_ed25519_engine_parent_class)->finalize(object);
}

static void
jcat_ed25519_engine_class_init(JcatEd25519EngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS(klass);
	klass_app->add_public_key = jcat_ed25519_engine_add_public_key;
	klass_app->add_public_key_raw = jcat_ed25519_engine_add_public_key_raw;
	klass_app->pubkey_verify = jcat_ed25519_engine_pubkey_verify;
	klass_app->pubkey_sign = jcat_ed25519_engine_pubkey_sign;
	klass_app->self_verify = jcat_ed25519_engine_self_verify;
	klass_app->self_sign = jcat_ed25519_engine_self_sign;
	object_class->finalize = jcat_ed25519_engine_finalize;
}

static void
jcat_ed25519_engine_init(JcatEd25519Engine *self)
{
	self->pubkeys = g_ptr_array_new_with_free_func(g_free);
}

JcatEngine *
jcat_ed25519_engine_new(JcatContext *context)
{
	g_return_val_if_fail(JCAT_IS_CONTEXT(context), NULL);
	return JCAT_ENGINE(g_object_new(JCAT_TYPE_ED25519_ENGINE,
					"context",
					context,
					"kind",
					JCAT_BLOB_KIND_ED25519,
					"method",
					JCAT_BLOB_METHOD_SIGNATURE,
					NULL));
}
