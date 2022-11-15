/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-bt-checkpoint-private.h"
#include "jcat-common-private.h"

struct _JcatBtCheckpoint {
	GObject parent_instance;
	gchar *origin;
	gchar *hash;
	guint log_size;
	GBytes *blob_pubkey;
	gchar *identity;
	GBytes *blob_signature;
	GBytes *blob_payload;
};

G_DEFINE_TYPE(JcatBtCheckpoint, jcat_bt_checkpoint, G_TYPE_OBJECT)

/**
 * jcat_bt_checkpoint_get_log_size:
 * @self: #JcatBtCheckpoint
 *
 * Gets the log_size.
 *
 * Returns: integer
 *
 * Since: 0.2.0
 **/
guint
jcat_bt_checkpoint_get_log_size(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), 0);
	return self->log_size;
}

/**
 * jcat_bt_checkpoint_get_origin:
 * @self: #JcatBtCheckpoint
 *
 * Gets the unique identifier for the log identity which issued the checkpoint.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.2.0
 **/
const gchar *
jcat_bt_checkpoint_get_origin(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->origin;
}

/**
 * jcat_bt_checkpoint_get_identity:
 * @self: #JcatBtCheckpoint
 *
 * Gets a human-readable representation of the signing ID.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.2.0
 **/
const gchar *
jcat_bt_checkpoint_get_identity(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->identity;
}

/**
 * jcat_bt_checkpoint_get_hash:
 * @self: #JcatBtCheckpoint
 *
 * Gets the first 4 bytes of the SHA256 hash of the associated public key to act as a hint in
 * identifying the correct key to verify with.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.2.0
 **/
const gchar *
jcat_bt_checkpoint_get_hash(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->hash;
}

/**
 * jcat_bt_checkpoint_get_pubkey:
 * @self: #JcatBtCheckpoint
 *
 * Gets the ED25519 public key blob.
 *
 * Returns: (transfer none): blob, or %NULL
 *
 * Since: 0.2.0
 **/
GBytes *
jcat_bt_checkpoint_get_pubkey(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->blob_pubkey;
}

/**
 * jcat_bt_checkpoint_get_signature:
 * @self: #JcatBtCheckpoint
 *
 * Gets the ED25519 public key blob.
 *
 * Returns: (transfer none): blob, or %NULL
 *
 * Since: 0.2.0
 **/
GBytes *
jcat_bt_checkpoint_get_signature(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->blob_signature;
}

/**
 * jcat_bt_checkpoint_get_payload:
 * @self: #JcatBtCheckpoint
 *
 * Gets the ED25519 public key blob.
 *
 * Returns: (transfer none): blob, or %NULL
 *
 * Since: 0.2.0
 **/
GBytes *
jcat_bt_checkpoint_get_payload(JcatBtCheckpoint *self)
{
	g_return_val_if_fail(JCAT_IS_BT_CHECKPOINT(self), NULL);
	return self->blob_payload;
}

/* private */
void
jcat_bt_checkpoint_add_string(JcatBtCheckpoint *self, guint idt, GString *str)
{
	jcat_string_append_kv(str, idt, G_OBJECT_TYPE_NAME(self), NULL);
	if (self->origin != NULL)
		jcat_string_append_kv(str, idt + 1, "Origin", self->origin);
	if (self->identity != NULL)
		jcat_string_append_kv(str, idt + 1, "OriginSignature", self->identity);
	if (self->log_size != 0)
		jcat_string_append_kx(str, idt + 1, "TreeSize", self->log_size);
	if (self->blob_pubkey != 0) {
		jcat_string_append_kx(str,
				      idt + 1,
				      "BlobPubkeySz",
				      g_bytes_get_size(self->blob_pubkey));
	}
	if (self->blob_signature != 0) {
		jcat_string_append_kx(str,
				      idt + 1,
				      "BlobSignatureSz",
				      g_bytes_get_size(self->blob_signature));
	}
	if (self->blob_payload != 0) {
		jcat_string_append_kx(str,
				      idt + 1,
				      "BlobPayloadSz",
				      g_bytes_get_size(self->blob_payload));
	}
}

/**
 * jcat_bt_checkpoint_to_string:
 * @self: #JcatBtCheckpoint
 *
 * Converts the #JcatBtCheckpoint to a string.
 *
 * Returns: string
 *
 * Since: 0.2.0
 **/
gchar *
jcat_bt_checkpoint_to_string(JcatBtCheckpoint *self)
{
	GString *str = g_string_new(NULL);
	jcat_bt_checkpoint_add_string(self, 0, str);
	return g_string_free(str, FALSE);
}

/**
 * jcat_bt_checkpoint_new:
 * @blob: a #GBytes
 * @error: (nullable): a #GError
 *
 * Converts the #JcatBtCheckpoint to a string.
 *
 * Returns: (transfer full): a #JcatBtCheckpoint, or %NULL on error
 *
 * Since: 0.2.0
 **/
JcatBtCheckpoint *
jcat_bt_checkpoint_new(GBytes *blob, GError **error)
{
	g_autofree gchar *blob_str = NULL;
	g_autofree guchar *pubkey = NULL;
	g_autofree guchar *sig = NULL;
	g_auto(GStrv) lines = NULL;
	g_auto(GStrv) sections = NULL;
	g_autoptr(GByteArray) payload = g_byte_array_new();
	g_autoptr(JcatBtCheckpoint) self = g_object_new(JCAT_TYPE_BT_CHECKPOINT, NULL);
	gsize pubkeysz = 0;
	gsize sigsz = 0;

	g_return_val_if_fail(blob != NULL, NULL);

	/* this is not always a NUL-terminated string */
	blob_str = g_strndup(g_bytes_get_data(blob, NULL), g_bytes_get_size(blob));
	lines = g_strsplit(blob_str, "\n", -1);
	if (g_strv_length(lines) != 6) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "invalid checkpoint format, lines %u",
			    g_strv_length(lines));
		return NULL;
	}

	/* add as strings */
	g_byte_array_append(payload, (const guint8 *)lines[0], strlen(lines[0]));
	g_byte_array_append(payload, (const guint8 *)"\n", 1);
	g_byte_array_append(payload, (const guint8 *)lines[1], strlen(lines[1]));
	g_byte_array_append(payload, (const guint8 *)"\n", 1);
	g_byte_array_append(payload, (const guint8 *)lines[2], strlen(lines[2]));
	g_byte_array_append(payload, (const guint8 *)"\n", 1);
	self->blob_payload = g_byte_array_free_to_bytes(g_steal_pointer(&payload));

	/* first two lines are trivial strings */
	self->origin = g_strdup(lines[0]);
	self->log_size = g_ascii_strtoull(lines[1], NULL, 10);

	/* ED25519 public key */
	pubkey = g_base64_decode(lines[2], &pubkeysz);
	if (pubkeysz != 32) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "invalid pubkey format, pubkeysz 0x%x",
			    (guint)pubkeysz);
		return NULL;
	}
	self->blob_pubkey = g_bytes_new(pubkey, pubkeysz);

	/* — ORIGIN BASE64 */
	sections = g_strsplit(lines[4], " ", 3);
	if (g_strv_length(sections) != 3 || g_strcmp0(sections[0], "—") != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "invalid checkpoint format, sections %x",
			    g_strv_length(sections));
		return NULL;
	}
	self->identity = g_strdup(sections[1]);
	sig = g_base64_decode(sections[2], &sigsz);
	if (sigsz != 64 + 4) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "invalid pubkey format, sigsz was 0x%x",
			    (guint)sigsz);
		return NULL;
	}
	self->hash = g_strdup_printf("%02x%02x%02x%02x", sig[0], sig[1], sig[2], sig[3]);
	self->blob_signature = g_bytes_new(sig + 0x4, sigsz - 0x4);

	/* success */
	return g_steal_pointer(&self);
}

static void
jcat_bt_checkpoint_finalize(GObject *object)
{
	JcatBtCheckpoint *self = JCAT_BT_CHECKPOINT(object);
	g_free(self->origin);
	g_free(self->identity);
	g_free(self->hash);
	if (self->blob_pubkey != NULL)
		g_bytes_unref(self->blob_pubkey);
	if (self->blob_signature != NULL)
		g_bytes_unref(self->blob_signature);
	if (self->blob_payload != NULL)
		g_bytes_unref(self->blob_payload);
	G_OBJECT_CLASS(jcat_bt_checkpoint_parent_class)->finalize(object);
}

static void
jcat_bt_checkpoint_class_init(JcatBtCheckpointClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = jcat_bt_checkpoint_finalize;
}

static void
jcat_bt_checkpoint_init(JcatBtCheckpoint *self)
{
}
