/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-bt-verifier-private.h"
#include "jcat-common-private.h"

struct _JcatBtVerifier {
	GObject parent_instance;
	gchar *name;
	gchar *hash;
	guint8 alg;
	GBytes *blob_key;
};

G_DEFINE_TYPE(JcatBtVerifier, jcat_bt_verifier, G_TYPE_OBJECT)

/**
 * jcat_bt_verifier_get_alg:
 * @self: #JcatBtVerifier
 *
 * Gets the algorithm ID.
 *
 * Returns: ID, typically 1
 *
 * Since: 0.2.0
 **/
guint8
jcat_bt_verifier_get_alg(JcatBtVerifier *self)
{
	g_return_val_if_fail(JCAT_IS_BT_VERIFIER(self), 0);
	return self->alg;
}

/**
 * jcat_bt_verifier_get_name:
 * @self: #JcatBtVerifier
 *
 * Gets the name.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.2.0
 **/
const gchar *
jcat_bt_verifier_get_name(JcatBtVerifier *self)
{
	g_return_val_if_fail(JCAT_IS_BT_VERIFIER(self), NULL);
	return self->name;
}

/**
 * jcat_bt_verifier_get_hash:
 * @self: #JcatBtVerifier
 *
 * Gets the hash.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.2.0
 **/
const gchar *
jcat_bt_verifier_get_hash(JcatBtVerifier *self)
{
	g_return_val_if_fail(JCAT_IS_BT_VERIFIER(self), NULL);
	return self->hash;
}

/**
 * jcat_bt_verifier_get_key:
 * @self: #JcatBtVerifier
 *
 * Gets the ED25519 public key blob.
 *
 * Returns: (transfer none): blob, or %NULL
 *
 * Since: 0.2.0
 **/
GBytes *
jcat_bt_verifier_get_key(JcatBtVerifier *self)
{
	g_return_val_if_fail(JCAT_IS_BT_VERIFIER(self), NULL);
	return self->blob_key;
}

/* private */
void
jcat_bt_verifier_add_string(JcatBtVerifier *self, guint idt, GString *str)
{
	jcat_string_append_kv(str, idt, G_OBJECT_TYPE_NAME(self), NULL);
	if (self->name != NULL)
		jcat_string_append_kv(str, idt + 1, "Name", self->name);
	if (self->hash != NULL)
		jcat_string_append_kv(str, idt + 1, "Hash", self->hash);
	if (self->alg != 0)
		jcat_string_append_kx(str, idt + 1, "AlgoId", self->alg);
	if (self->blob_key != 0) {
		jcat_string_append_kx(str, idt + 1, "KeySz", g_bytes_get_size(self->blob_key));
	}
}

/**
 * jcat_bt_verifier_to_string:
 * @self: #JcatBtVerifier
 *
 * Converts the #JcatBtVerifier to a string.
 *
 * Returns: string
 *
 * Since: 0.2.0
 **/
gchar *
jcat_bt_verifier_to_string(JcatBtVerifier *self)
{
	GString *str = g_string_new(NULL);
	jcat_bt_verifier_add_string(self, 0, str);
	return g_string_free(str, FALSE);
}

/**
 * jcat_bt_verifier_new:
 * @blob: a #GBytes
 * @error: (nullable): a #GError
 *
 * Converts the #JcatBtVerifier to a string.
 *
 * Returns: (transfer full): a #JcatBtVerifier, or %NULL on error
 *
 * Since: 0.2.0
 **/
JcatBtVerifier *
jcat_bt_verifier_new(GBytes *blob, GError **error)
{
	gsize pubkey_rawsz = 0;
	g_autofree gchar *blob_str = NULL;
	g_autofree guchar *pubkey_raw = NULL;
	g_auto(GStrv) sections = NULL;
	g_autoptr(JcatBtVerifier) self = g_object_new(JCAT_TYPE_BT_VERIFIER, NULL);

	g_return_val_if_fail(blob != NULL, NULL);

	/* this is not a NUL-terminated string */
	blob_str = g_strndup(g_bytes_get_data(blob, NULL), g_bytes_get_size(blob));
	sections = g_strsplit(blob_str, "+", 3);
	if (g_strv_length(sections) != 3) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "invalid pubkey format");
		return NULL;
	}

	/* first two sections are trivial strings */
	self->name = g_strdup(sections[0]);
	self->hash = g_strdup(sections[1]);

	/* algorithm ID then ED25519 public key */
	pubkey_raw = g_base64_decode(sections[2], &pubkey_rawsz);
	if (pubkey_rawsz != 33) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "invalid pubkey format");
		return NULL;
	}
	self->alg = pubkey_raw[0];
	self->blob_key = g_bytes_new(pubkey_raw + 1, pubkey_rawsz - 1);

	/* success */
	return g_steal_pointer(&self);
}

static void
jcat_bt_verifier_finalize(GObject *object)
{
	JcatBtVerifier *self = JCAT_BT_VERIFIER(object);
	g_free(self->name);
	g_free(self->hash);
	if (self->blob_key != NULL)
		g_bytes_unref(self->blob_key);
	G_OBJECT_CLASS(jcat_bt_verifier_parent_class)->finalize(object);
}

static void
jcat_bt_verifier_class_init(JcatBtVerifierClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = jcat_bt_verifier_finalize;
}

static void
jcat_bt_verifier_init(JcatBtVerifier *self)
{
}
