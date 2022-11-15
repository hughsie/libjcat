/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <string.h>

#include <gnutls/crypto.h>
#include <nettle/eddsa.h>
#include <string.h>

#include "jcat-common-private.h"
#include "jcat-ed25519-engine.h"
#include "jcat-engine-private.h"

struct _JcatEd25519Engine {
	JcatEngine parent_instance;
	GPtrArray *pubkeys; /* of Ed25519Key */
};

typedef unsigned char Ed25519Key[ED25519_KEY_SIZE];
typedef unsigned char Ed25519Sig[ED25519_SIGNATURE_SIZE];

G_DEFINE_TYPE(JcatEd25519Engine, jcat_ed25519_engine, JCAT_TYPE_ENGINE)

static GBytes *
jcat_ed25519_sig_to_bytes(const Ed25519Sig privkey)
{
	return g_bytes_new(privkey, sizeof(Ed25519Sig));
}

static gboolean
jcat_ed25519_sig_from_bytes(GBytes *blob, Ed25519Sig privkey, GError **error)
{
	if (g_bytes_get_size(blob) != sizeof(Ed25519Sig)) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "invalid privkey size");
		return FALSE;
	}
	memcpy(privkey, g_bytes_get_data(blob, NULL), sizeof(Ed25519Sig));
	return TRUE;
}

static GBytes *
jcat_ed25519_key_to_bytes(const Ed25519Key pubkey)
{
	return g_bytes_new(pubkey, sizeof(Ed25519Key));
}

static gboolean
jcat_ed25519_key_from_bytes(GBytes *blob, Ed25519Key pubkey, GError **error)
{
	if (g_bytes_get_size(blob) != sizeof(Ed25519Key)) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "invalid pubkey size");
		return FALSE;
	}
	memcpy(pubkey, g_bytes_get_data(blob, NULL), sizeof(Ed25519Key));
	return TRUE;
}

static gboolean
jcat_ed25519_engine_add_public_key_raw(JcatEngine *engine, GBytes *blob, GError **error)
{
	JcatEd25519Engine *self = JCAT_ED25519_ENGINE(engine);
	g_autofree Ed25519Key *pubkey = g_new0(Ed25519Key, 1);
	if (!jcat_ed25519_key_from_bytes(blob, *pubkey, error))
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
	Ed25519Sig sig = {0};

	/* sanity check */
	if (self->pubkeys->len == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "no keys in keyring");
		return NULL;
	}
	if (!jcat_ed25519_sig_from_bytes(blob_signature, sig, error))
		return NULL;

	/* verifies against any of the public keys */
	for (guint i = 0; i < self->pubkeys->len; i++) {
		Ed25519Key *pubkey = g_ptr_array_index(self->pubkeys, i);
		if (ed25519_sha512_verify(*pubkey,
					  g_bytes_get_size(blob),
					  g_bytes_get_data(blob, NULL),
					  sig) != 0) {
			return JCAT_RESULT(g_object_new(JCAT_TYPE_RESULT, "engine", engine, NULL));
		}
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
	Ed25519Key pubkey = {0};
	Ed25519Sig privkey = {0};
	Ed25519Sig sig = {0};
	g_autoptr(GBytes) blob_sig = NULL;

	/* nothing to do */
	if (g_bytes_get_size(blob) == 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "nothing to do");
		return NULL;
	}

	/* load */
	if (!jcat_ed25519_sig_from_bytes(blob_privkey, privkey, error))
		return NULL;
	if (!jcat_ed25519_key_from_bytes(blob_cert, pubkey, error))
		return NULL;

	/* simple */
	ed25519_sha512_sign(pubkey,
			    privkey,
			    g_bytes_get_size(blob),
			    g_bytes_get_data(blob, NULL),
			    sig);
	blob_sig = jcat_ed25519_sig_to_bytes(sig);
	return jcat_blob_new(JCAT_BLOB_KIND_ED25519, blob_sig);
}

static JcatResult *
jcat_ed25519_engine_self_verify(JcatEngine *engine,
				GBytes *blob,
				GBytes *blob_signature,
				JcatVerifyFlags flags,
				GError **error)
{
	Ed25519Key pubkey = {0};
	Ed25519Sig sig = {0};
	const gchar *keyring_path = jcat_engine_get_keyring_path(engine);
	g_autofree gchar *fn_pubkey = NULL;
	g_autoptr(GBytes) blob_pubkey = NULL;

	fn_pubkey = g_build_filename(keyring_path, "pki", "public.ed25519", NULL);
	blob_pubkey = jcat_get_contents_bytes(fn_pubkey, error);
	if (blob_pubkey == NULL)
		return NULL;
	if (!jcat_ed25519_key_from_bytes(blob_pubkey, pubkey, error))
		return NULL;
	if (!jcat_ed25519_sig_from_bytes(blob_signature, sig, error))
		return NULL;
	if (ed25519_sha512_verify(pubkey,
				  g_bytes_get_size(blob),
				  g_bytes_get_data(blob, NULL),
				  sig) == 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to verify data");
		return NULL;
	}

	/* success */
	return JCAT_RESULT(g_object_new(JCAT_TYPE_RESULT, "engine", engine, NULL));
}

static JcatBlob *
jcat_ed25519_engine_self_sign(JcatEngine *engine, GBytes *blob, JcatSignFlags flags, GError **error)
{
	Ed25519Key pubkey = {0};
	Ed25519Sig privkey = {0};
	Ed25519Sig sig = {0};
	const gchar *keyring_path = jcat_engine_get_keyring_path(engine);
	g_autofree gchar *fn_privkey = NULL;
	g_autofree gchar *fn_pubkey = NULL;
	g_autoptr(GBytes) blob_privkey = NULL;
	g_autoptr(GBytes) blob_pubkey = NULL;
	g_autoptr(GBytes) blob_sig = NULL;

	/* check keypair exists, otherwise generate and save */
	fn_privkey = g_build_filename(keyring_path, "pki", "secret.ed25519", NULL);
	fn_pubkey = g_build_filename(keyring_path, "pki", "public.ed25519", NULL);
	if (!g_file_test(fn_privkey, G_FILE_TEST_EXISTS)) {
		gint rc;

		/* randomize contents */
		rc = gnutls_rnd(GNUTLS_RND_KEY, privkey, sizeof(Ed25519Sig));
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "failed to generate private key: %s [%i]",
				    gnutls_strerror(rc),
				    rc);
			return NULL;
		}
		ed25519_sha512_public_key(pubkey, privkey);
		if (!jcat_mkdir_parent(fn_privkey, error))
			return NULL;
		blob_privkey = jcat_ed25519_sig_to_bytes(privkey);
		if (!jcat_set_contents_bytes(fn_privkey, blob_privkey, error))
			return NULL;
		blob_pubkey = jcat_ed25519_key_to_bytes(pubkey);
		if (!jcat_set_contents_bytes(fn_pubkey, blob_pubkey, error))
			return NULL;
	} else {
		blob_privkey = jcat_get_contents_bytes(fn_privkey, error);
		if (blob_privkey == NULL)
			return NULL;
		if (!jcat_ed25519_sig_from_bytes(blob_privkey, privkey, error))
			return NULL;
		blob_pubkey = jcat_get_contents_bytes(fn_pubkey, error);
		if (blob_pubkey == NULL)
			return NULL;
		if (!jcat_ed25519_key_from_bytes(blob_pubkey, pubkey, error))
			return NULL;
	}

	/* simple */
	ed25519_sha512_sign(pubkey,
			    privkey,
			    g_bytes_get_size(blob),
			    g_bytes_get_data(blob, NULL),
			    sig);
	blob_sig = jcat_ed25519_sig_to_bytes(sig);
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
