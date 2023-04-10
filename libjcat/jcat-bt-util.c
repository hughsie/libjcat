/*
 * Copyright (C) 2023 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <arpa/inet.h>
#include <gio/gio.h>

#include "jcat-bt-util.h"
#include "jcat-proof-bits-private.h"

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

/* Algorithm identifier: 1 for Ed25519. See
 * https://cs.opensource.google/go/x/mod/+/refs/tags/v0.9.0:sumdb/note/note.go;l=232;drc=ad6fd61f94f8fdf6926f5dee6e45bdd13add2f9f
 */
static const guint8 ed25519_id = 1;

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

/**
 * jcat_bt_parse_private_key:
 * @private_key_file_content: (not nullable): the entire file content of the private key
 * @parsed_private_key: (not nullable) (out): the buffer for the private key
 * @parsed_public_key: (not nullable) (out): the buffer for the public key
 * @parsed_key_name: (not nullable) (out): the name of the key
 * @parsed_key_hash: (not nullable) (out): the 32-bit hash of the key
 * @error: #GError, or %NULL
 *
 * Parse a private key in the same format as Go's sumdb. This works with the output of
 *jcat_bt_generate_key_pair.
 *
 * Since: 0.1.12
 **/
gboolean
jcat_bt_parse_private_key(GBytes *private_key_file_content,
			  GByteArray **parsed_private_key,
			  GByteArray **parsed_public_key,
			  gchar **parsed_key_name,
			  gchar **parsed_key_hash,
			  GError **error)
{
#ifndef ENABLE_ED25519
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    __FUNCTION__ " requires Ed25519 support but it is not enabled");
	return FALSE;
#else

	const guint8 *data = NULL;
	gsize size = 0;
	const guint8 *next = NULL, *key_hash = NULL;
	gsize key_name_size = 0;
	static const gsize key_hash_size = 8;
	g_autoptr(GString) base64_private = NULL;
	g_autofree guchar *private = NULL;
	gsize private_len = 0;
	g_autoptr(GByteArray) public_key_for_validation = NULL;
	g_autofree gchar *expected_key_hash = NULL;
	gsize i;

	static const gchar prefix[] = "PRIVATE+KEY+";

	/* Looks like this: "PRIVATE+KEY+test+3d18b207+AXLw43DfQRIa8AB0FwAyP0clTh437+DCXuAg4FUb55LI"
	 */

	g_return_val_if_fail(parsed_private_key != NULL, FALSE);
	g_return_val_if_fail(parsed_public_key != NULL, FALSE);
	g_return_val_if_fail(parsed_key_name != NULL, FALSE);
	g_return_val_if_fail(parsed_key_hash != NULL, FALSE);

	data = g_bytes_get_data(private_key_file_content, &size);
	if (size < sizeof prefix) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "too short to be a private key");
		return FALSE;
	}
	if (memcmp(data, prefix, sizeof prefix - 1) != 0) {
		g_set_error_literal(
		    error,
		    G_IO_ERROR,
		    G_IO_ERROR_FAILED,
		    "unexpected private key format; must start with \"PRIVATE+KEY+\"");
		return FALSE;
	}

	data += sizeof prefix - 1;
	size -= sizeof prefix - 1;

	/* The next field is the key name. */
	next = memchr(data, '+', size);
	if (next == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of key name");
		return FALSE;
	}
	if (*parsed_key_name) {
		g_free(*parsed_key_name);
	}
	*parsed_key_name = g_strndup((const gchar *)data, next - data);
	key_name_size = next - data;

	data += key_name_size + 1;
	size -= key_name_size + 1;

	/* The next field is the key hash. */
	next = memchr(data, '+', size);
	if (next == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of key hash");
		return FALSE;
	}
	if (next != data + key_hash_size) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "incorrect size for key hash; want %zu got %ld",
			    key_hash_size,
			    next - data);
		return FALSE;
	}
	key_hash = data;
	for (; data != next; ++data, --size) {
		if (!((*data >= '0' && *data <= '9') || (*data >= 'a' && *data <= 'f') ||
		      (*data >= 'A' && *data <= 'F'))) {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "key hash must be hexadecimal");
			return FALSE;
		}
	}

	++data;
	--size;

	/* The final field is the base64-encoded key content. Need to be NULL-terminated.*/
	base64_private = g_string_new_len((const gchar *)data, size);
	for (; size > 0; ++data, --size) {
		if (!g_ascii_isalnum(*data) && *data != '+' && *data != '/') {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "incorrect base64 encoding");
			return FALSE;
		}
	}
	private = g_base64_decode(base64_private->str, &private_len);
	if (private_len != 1 + ED25519_KEY_SIZE) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "unexpected size for private key");
		return FALSE;
	}
	if (*private != 1) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "unsupported key type; want Ed25519");
		return FALSE;
	}

	_g_set_byte_array(parsed_private_key,
			  g_byte_array_append(g_byte_array_new(), private + 1, ED25519_KEY_SIZE));
	_g_set_byte_array(parsed_public_key,
			  g_byte_array_set_size(g_byte_array_new(), ED25519_KEY_SIZE));

	ed25519_sha512_public_key((*parsed_public_key)->data, (*parsed_private_key)->data);

	/* Check the key hash */
	public_key_for_validation = g_byte_array_new();
	public_key_for_validation = g_byte_array_append(public_key_for_validation, &ed25519_id, 1);
	public_key_for_validation = g_byte_array_append(public_key_for_validation,
							(*parsed_public_key)->data,
							(*parsed_public_key)->len);
	expected_key_hash = generate_key_hash(*parsed_key_name, public_key_for_validation);
	if (memcmp(expected_key_hash, key_hash, key_hash_size) != 0) {
		g_set_error(
		    error,
		    G_IO_ERROR,
		    G_IO_ERROR_FAILED,
		    "Mismatching key hash: provided key hash does not match expected key hash %s",
		    expected_key_hash);
		return FALSE;
	}
	if (*parsed_key_hash) {
		g_free(*parsed_key_hash);
	}
	*parsed_key_hash = g_new(char, 1 + key_hash_size / 2);
	for (i = 0; i < key_hash_size / 2; ++i) {
		(*parsed_key_hash)[i] = (g_ascii_xdigit_value(expected_key_hash[2 * i]) << 4) |
					g_ascii_xdigit_value(expected_key_hash[2 * i + 1]);
	}
	(*parsed_key_hash)[4] = '\0';

	return TRUE;
#endif
}

static GBytes *
sign_note(GString *text,
	  GByteArray *parsed_public_key,
	  GByteArray *parsed_private_key,
	  gchar *parsed_key_name,
	  gchar *parsed_key_hash,
	  GError **error)
{
#ifndef ENABLE_ED25519
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    __FUNCTION__ " requires Ed25519 support but it is not enabled");
	return FALSE;
#else

	/* Creates a signed note in the Go sumdb format. */
	GByteArray *buf = NULL;
	g_autoptr(GByteArray) raw_signature = g_byte_array_set_size(g_byte_array_new(), 64);
	g_autofree gchar *encoded_signature = NULL;
	g_autoptr(GString) formatted_signature = g_string_new(NULL);

	g_return_val_if_fail(text != NULL, NULL);
	g_return_val_if_fail(parsed_private_key != NULL, NULL);
	g_return_val_if_fail(parsed_key_name != NULL, NULL);
	g_return_val_if_fail(parsed_key_hash != NULL, NULL);

	/* Require the text to end with a newline */
	if (text->len == 0 || text->str[text->len - 1] != '\n') {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Cannot sign: text must end with a newline");
		return NULL;
	}

	ed25519_sha512_sign(parsed_public_key->data,
			    parsed_private_key->data,
			    text->len,
			    (const guint8 *)text->str,
			    raw_signature->data);

	/* Add the key hash prior to the signature */
	g_byte_array_prepend(raw_signature, (const guint8 *)parsed_key_hash, 4);

	encoded_signature = g_base64_encode(raw_signature->data, raw_signature->len);

	/* Add text and an extra new line (need two consecutive newlines) */
	buf = g_byte_array_new();
	g_byte_array_append(buf, (const guint8 *)text->str, text->len);
	g_byte_array_append(buf, (const guint8 *)"\n", 1);

	/* Format the signature */
	g_string_printf(formatted_signature,
			"\xe2\x80\x94 %s %s\n",
			parsed_key_name,
			encoded_signature);
	g_byte_array_append(buf,
			    (const guint8 *)formatted_signature->str,
			    formatted_signature->len);
	return g_byte_array_free_to_bytes(buf);
#endif
}

/*
 The on-disk structure is:

	<rootDir>/leaves/aa/bb/cc/ddeeff...
	<rootDir>/leaves/pending/aabbccddeeff...
	<rootDir>/seq/aa/bb/cc/ddeeff...
	<rootDir>/tile/<level>/aa/bb/ccddee...
	<rootDir>/checkpoint
 */

static gboolean
create_storage(GFile *storage_dir, GError **error)
{
	gboolean ret;
	g_autoptr(GFile) seq_dir = NULL;
	g_autoptr(GFile) tile_dir = NULL;
	g_autoptr(GFile) leaves_dir = NULL;
	g_autoptr(GFile) pending_dir = NULL;

	ret = g_file_make_directory_with_parents(storage_dir, NULL, error);
	if (!ret)
		return FALSE;

	/* Create necessary subdirectories */
	seq_dir = g_file_get_child(storage_dir, "seq");
	ret = g_file_make_directory(seq_dir, NULL, error);
	if (!ret)
		return FALSE;

	tile_dir = g_file_get_child(storage_dir, "tile");
	ret = g_file_make_directory(tile_dir, NULL, error);
	if (!ret)
		return FALSE;

	leaves_dir = g_file_get_child(storage_dir, "leaves");
	ret = g_file_make_directory(leaves_dir, NULL, error);
	if (!ret)
		return FALSE;

	pending_dir = g_file_get_child(leaves_dir, "pending");
	ret = g_file_make_directory(pending_dir, NULL, error);
	if (!ret)
		return FALSE;

	return TRUE;
}

static GString *
format_checkpoint(const gchar *cp_origin, guint64 cp_size, GBytes *cp_hash)
{
	GString *ret = g_string_new(NULL);
	g_autofree gchar *encoded_hash = NULL;

	gconstpointer hash_data = NULL;
	gsize hash_size = 0;

	hash_data = g_bytes_get_data(cp_hash, &hash_size);
	encoded_hash = g_base64_encode(hash_data, hash_size);
	g_string_printf(ret, "%s\n%lu\n%s\n", cp_origin, cp_size, encoded_hash);
	return ret;
}

static const guchar empty_root[32] = {
    /* echo -n ''|sha256sum|xxd -p -r|xxd -i */
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

/**
 * jcat_bt_integrate_init:
 * @storage_dir: (not nullable): the root directory for the storage
 * @private_key_contents: (not nullable): the contents of the private key
 * @origin: (not nullable): the log origin string to use in produced checkpoint
 * @error: #GError, or %NULL
 *
 * Initialize an on-disk storage directory with an initial checkpoint.
 *
 * Since: 0.1.12
 **/
gboolean
jcat_bt_integrate_init(GFile *storage_dir,
		       GBytes *private_key_contents,
		       const gchar *cp_origin,
		       GError **error)
{
	gboolean ret;
	g_autoptr(GByteArray) parsed_private_key = NULL;
	g_autoptr(GByteArray) parsed_public_key = NULL;
	g_autofree gchar *parsed_key_name = NULL;
	g_autofree gchar *parsed_key_hash = NULL;

	guint64 cp_size = 0;
	g_autoptr(GBytes) cp_hash = NULL;

	g_autoptr(GString) marshalled_checkpoint = NULL;
	g_autoptr(GBytes) signed_checkpoint = NULL;

	g_autoptr(GFile) checkpoint_file = NULL;
	g_autofree gchar *checkpoint_file_path = NULL;

	ret = create_storage(storage_dir, error);
	if (!ret) {
		g_prefix_error(error, "failed to create directories for storage: ");
		return FALSE;
	}

	ret = jcat_bt_parse_private_key(private_key_contents,
					&parsed_private_key,
					&parsed_public_key,
					&parsed_key_name,
					&parsed_key_hash,
					error);
	if (!ret) {
		g_prefix_error(error, "failed to parse private key: ");
		return FALSE;
	}

	/* When initializing, the checkpoint has an empty root. */
	cp_hash = g_bytes_new_static(empty_root, sizeof empty_root);

	/* Marshall the checkpoint into a string format */
	marshalled_checkpoint = format_checkpoint(cp_origin, cp_size, cp_hash);

	/* Sign it */
	signed_checkpoint = sign_note(marshalled_checkpoint,
				      parsed_public_key,
				      parsed_private_key,
				      parsed_key_name,
				      parsed_key_hash,
				      error);
	if (signed_checkpoint == NULL) {
		g_prefix_error(error, "failed to sign checkpoint: ");
		return FALSE;
	}

	/* Write the checkpoint to disk safely */
	checkpoint_file = g_file_get_child(storage_dir, "checkpoint");
	checkpoint_file_path = g_file_get_path(checkpoint_file);
	ret = g_file_set_contents_full(checkpoint_file_path,
				       g_bytes_get_data(signed_checkpoint, NULL),
				       g_bytes_get_size(signed_checkpoint),
				       G_FILE_SET_CONTENTS_CONSISTENT,
				       0644,
				       error);
	if (!ret) {
		g_prefix_error(error, "failed to write to filesystem: ");
		return FALSE;
	}

	return TRUE;
}
