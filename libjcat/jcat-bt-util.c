/*
 * Copyright (C) 2023 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gio/gio.h>

#include "jcat-bt-util.h"

#ifdef ENABLE_ED25519
#include <gnutls/crypto.h>
#include <nettle/eddsa.h>
#endif

#ifdef ENABLE_ED25519
static gboolean
generate_ed25519_key(GByteArray **raw_public_key, GByteArray **raw_private_key, GError **error)
{
	gint rc;

	*raw_public_key = g_byte_array_set_size(g_byte_array_new(), ED25519_KEY_SIZE);
	*raw_private_key = g_byte_array_set_size(g_byte_array_new(), ED25519_KEY_SIZE);

	rc = gnutls_rnd(GNUTLS_RND_KEY, (*raw_private_key)->data, ED25519_KEY_SIZE);
	if (rc < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "failed to generate private key: %s [%i]",
			    gnutls_strerror(rc),
			    rc);
		return FALSE;
	}

	ed25519_sha512_public_key((*raw_public_key)->data, (*raw_private_key)->data);
	return TRUE;
}

static gchar *
generate_key_hash(const gchar *name, GByteArray *pubkey)
{
	/* The key hash is defined as the first four bytes of the SHA256 checksum of the string
	 * "name", a newline, and the public key. See
	 * https://cs.opensource.google/go/x/mod/+/refs/tags/v0.9.0:sumdb/note/note.go;l=216-223;drc=ad6fd61f94f8fdf6926f5dee6e45bdd13add2f9f
	 */
	gchar *checksum = NULL;
	static const gchar *const separator = "\n";
	g_autoptr(GBytes) data = NULL;

	GByteArray *data_array = g_byte_array_new();
	g_byte_array_append(data_array, (const guint8 *)name, strlen(name));
	g_byte_array_append(data_array, (const guint8 *)separator, strlen(separator));
	g_byte_array_append(data_array, pubkey->data, pubkey->len);

	data = g_byte_array_free_to_bytes(data_array);
	checksum = g_compute_checksum_for_bytes(G_CHECKSUM_SHA256, data);

	/* This is the full checksum in hexadecimal. But we only require the first four bytes
	 * encoded (eight bytes). */
	checksum[8] = '\0';

	return checksum;
}
#endif

/**
 * jcat_bt_generate_key_pair:
 * @keyname: (not nullable): the human-readable name of the key
 * @public_key: (not nullable) (out): the buffer for the public key
 * @private_key: (not nullable) (out): the buffer for the private key
 * @error: #GError, or %NULL
 *
 * Create a key pair in the same format as Go's sumdb.
 *
 * Since: 0.1.12
 **/
gboolean
jcat_bt_generate_key_pair(const gchar *keyname,
			  GBytes **public_key,
			  GBytes **private_key,
			  GError **error)
{
#ifndef ENABLE_ED25519
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    __FUNCTION__ " requires Ed25519 support but it is not enabled");
	return FALSE;
#else

	/* The generate-key command generates a key in the same format as Go's note package. See
	 * https://cs.opensource.google/go/x/mod/+/refs/tags/v0.9.0:sumdb/note/note.go;l=362;drc=ad6fd61f94f8fdf6926f5dee6e45bdd13add2f9f
	 */

	GString *public_key_string = NULL;
	GString *private_key_string = NULL;

	g_autoptr(GByteArray) raw_public_key = NULL;
	g_autoptr(GByteArray) raw_private_key = NULL;

	g_autofree gchar *key_hash = NULL;
	g_autofree gchar *encoded_raw_public_key = NULL;
	g_autofree gchar *encoded_raw_private_key = NULL;

	/* Algorithm identifier: 1 for Ed25519. See
	 * https://cs.opensource.google/go/x/mod/+/refs/tags/v0.9.0:sumdb/note/note.go;l=232;drc=ad6fd61f94f8fdf6926f5dee6e45bdd13add2f9f
	 */
	static const guint8 ed25519_id = 1;

	g_return_val_if_fail(public_key != NULL, FALSE);
	g_return_val_if_fail(private_key != NULL, FALSE);
	g_return_val_if_fail(keyname != NULL, FALSE);

	generate_ed25519_key(&raw_public_key, &raw_private_key, error);

	raw_public_key = g_byte_array_prepend(raw_public_key, &ed25519_id, 1);
	raw_private_key = g_byte_array_prepend(raw_private_key, &ed25519_id, 1);

	/* key hash */
	key_hash = generate_key_hash(keyname, raw_public_key);

	encoded_raw_public_key = g_base64_encode(raw_public_key->data, raw_public_key->len);
	encoded_raw_private_key = g_base64_encode(raw_private_key->data, raw_private_key->len);

	/* formatted key contents */
	private_key_string = g_string_new(NULL);
	public_key_string = g_string_new(NULL);
	g_string_printf(private_key_string,
			"PRIVATE+KEY+%s+%s+%s",
			keyname,
			key_hash,
			encoded_raw_private_key);
	g_string_printf(public_key_string, "%s+%s+%s", keyname, key_hash, encoded_raw_public_key);
	if (*public_key)
		g_bytes_unref(*public_key);
	if (*private_key)
		g_bytes_unref(*private_key);
	*private_key = g_string_free_to_bytes(private_key_string);
	*public_key = g_string_free_to_bytes(public_key_string);

	return TRUE;
#endif
}
