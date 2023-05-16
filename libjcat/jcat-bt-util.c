/*
 * Copyright (C) 2023 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <gio/gio.h>
#include <string.h>

#include "jcat-bt-util.h"
#include "jcat-common-private.h"
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

static gboolean
parse_key_name(const guint8 **data, gsize *size, gchar **parsed_key_name, GError **error)
{
	gsize key_name_size;
	const guint8 *next = memchr(*data, '+', *size);
	if (next == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of key name");
		return FALSE;
	}
	if (next == *data) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "key name cannot be empty");
		return FALSE;
	}
	*parsed_key_name = g_strndup((const gchar *)*data, next - *data);
	key_name_size = next - *data;

	*data += key_name_size + 1;
	*size -= key_name_size + 1;
	return TRUE;
}

static gboolean
parse_key_hash(const guint8 **data,
	       gsize *size,
	       const guint8 **parsed_unvalidated_key_hash,
	       GError **error)
{
	static const gsize key_hash_size = 8;
	const guint8 *next = memchr(*data, '+', *size);
	if (next == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of key hash");
		return FALSE;
	}
	if (next != *data + key_hash_size) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "incorrect size for key hash; want %zu got %ld",
			    key_hash_size,
			    next - *data);
		return FALSE;
	}
	*parsed_unvalidated_key_hash = *data;

	for (; *data != next; ++*data, --*size) {
		if (!g_ascii_isxdigit(**data)) {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "key hash must be hexadecimal");
			return FALSE;
		}
	}

	++*data;
	--*size;

	return TRUE;
}

static gboolean
validate_parsed_key(GByteArray *parsed_public_key,
		    const gchar *parsed_key_name,
		    const guint8 *key_hash,
		    gchar **parsed_key_hash,
		    GError **error)
{
	static const gsize key_hash_size = 8;
	g_autoptr(GByteArray) public_key_for_validation = NULL;
	g_autofree gchar *expected_key_hash = NULL;
	gsize i;

	public_key_for_validation = g_byte_array_new();
	public_key_for_validation = g_byte_array_append(public_key_for_validation, &ed25519_id, 1);
	public_key_for_validation = g_byte_array_append(public_key_for_validation,
							parsed_public_key->data,
							parsed_public_key->len);
	expected_key_hash = generate_key_hash(parsed_key_name, public_key_for_validation);
	if (memcmp(expected_key_hash, key_hash, key_hash_size) != 0) {
		g_set_error(
		    error,
		    G_IO_ERROR,
		    G_IO_ERROR_FAILED,
		    "Mismatching key hash: provided key hash does not match expected key hash %s",
		    expected_key_hash);
		return FALSE;
	}

	*parsed_key_hash = g_new(char, 1 + key_hash_size / 2);
	for (i = 0; i < key_hash_size / 2; ++i) {
		(*parsed_key_hash)[i] = (g_ascii_xdigit_value(expected_key_hash[2 * i]) << 4) |
					g_ascii_xdigit_value(expected_key_hash[2 * i + 1]);
	}
	(*parsed_key_hash)[4] = '\0';

	return TRUE;
}

static GByteArray *
parse_key_content(const guint8 *data, gsize size, GError **error)
{
	/* NOTE: this function can parse both private and public key content */
	g_autoptr(GString) base64_key = g_string_new_len((const gchar *)data, size);
	g_autofree guchar *decoded = NULL;
	gsize decoded_len = 0;
	for (; size > 0; ++data, --size) {
		if (!g_ascii_isalnum(*data) && *data != '+' && *data != '/') {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "incorrect base64 encoding");
			return NULL;
		}
	}

	decoded = g_base64_decode(base64_key->str, &decoded_len);
	if (decoded_len != 1 + ED25519_KEY_SIZE) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "unexpected size for key");
		return NULL;
	}
	if (*decoded != 1) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "unsupported key type; want Ed25519");
		return NULL;
	}
	return g_byte_array_append(g_byte_array_new(), decoded + 1, ED25519_KEY_SIZE);
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
	const guint8 *key_hash = NULL;
	g_autoptr(GString) base64_private = NULL;
	g_autoptr(GByteArray) decoded_key_content = NULL;

	static const gchar prefix[] = "PRIVATE+KEY+";

	/* Looks like this: "PRIVATE+KEY+test+3d18b207+AXLw43DfQRIa8AB0FwAyP0clTh437+DCXuAg4FUb55LI"
	 */

	g_return_val_if_fail(parsed_private_key != NULL, FALSE);
	g_return_val_if_fail(parsed_public_key != NULL, FALSE);
	g_return_val_if_fail(parsed_key_name != NULL, FALSE);
	g_return_val_if_fail(parsed_key_hash != NULL, FALSE);

	g_free(*parsed_key_name);
	*parsed_key_name = NULL;
	g_free(*parsed_key_hash);
	*parsed_key_hash = NULL;

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
	if (!parse_key_name(&data, &size, parsed_key_name, error))
		return FALSE;

	/* The next field is the key hash. */
	if (!parse_key_hash(&data, &size, &key_hash, error))
		return FALSE;

	/* The final field is the base64-encoded key content. Need to be NULL-terminated.*/
	decoded_key_content = parse_key_content(data, size, error);
	if (decoded_key_content == NULL)
		return FALSE;

	_g_set_byte_array(parsed_private_key, decoded_key_content);
	_g_set_byte_array(parsed_public_key,
			  g_byte_array_set_size(g_byte_array_new(), ED25519_KEY_SIZE));

	/* Calculate the public key from the private key */
	ed25519_sha512_public_key((*parsed_public_key)->data, (*parsed_private_key)->data);

	/* Check the key hash */
	if (!validate_parsed_key(*parsed_public_key,
				 *parsed_key_name,
				 key_hash,
				 parsed_key_hash,
				 error))
		return FALSE;

	return TRUE;
#endif
}

/**
 * jcat_bt_parse_public_key:
 * @public_key_file_content: (not nullable): the entire file content of the public key
 * @parsed_public_key: (not nullable) (out): the buffer for the public key
 * @parsed_key_name: (not nullable) (out): the name of the key
 * @parsed_key_hash: (not nullable) (out): the 32-bit hash of the key
 * @error: #GError, or %NULL
 *
 * Parse a public key in the same format as Go's sumdb. This works with the output of
 * jcat_bt_generate_key_pair. Note that if the private key is already being parsed, it is not
 * necessary to parse the public key afterwards since the public key can be found from the private
 * key.
 *
 * Since: 0.1.12
 **/
gboolean
jcat_bt_parse_public_key(GBytes *public_key_file_content,
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
	const guint8 *key_hash = NULL;
	g_autoptr(GByteArray) decoded_key_content = NULL;

	/* Looks like this: "test+69fd7e09+AXiHgzPfdDlQURC7UegWXKUFdjir/GC7uv45fTMEk5IN" */
	g_return_val_if_fail(parsed_public_key != NULL, FALSE);
	g_return_val_if_fail(parsed_key_name != NULL, FALSE);
	g_return_val_if_fail(parsed_key_hash != NULL, FALSE);

	g_free(*parsed_key_name);
	*parsed_key_name = NULL;
	g_free(*parsed_key_hash);
	*parsed_key_hash = NULL;

	data = g_bytes_get_data(public_key_file_content, &size);

	/* The next field is the key name. */
	if (!parse_key_name(&data, &size, parsed_key_name, error))
		return FALSE;

	/* The next field is the key hash. */
	if (!parse_key_hash(&data, &size, &key_hash, error))
		return FALSE;

	/* The final field is the base64-encoded key content. Need to be NULL-terminated.*/
	decoded_key_content = parse_key_content(data, size, error);
	if (decoded_key_content == NULL)
		return FALSE;

	_g_set_byte_array(parsed_public_key, decoded_key_content);

	/* Check the key hash */
	if (!validate_parsed_key(*parsed_public_key,
				 *parsed_key_name,
				 key_hash,
				 parsed_key_hash,
				 error))
		return FALSE;

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

static const gchar *
memrmem(const gchar *haystack, gsize haystack_size, const gchar *needle, gsize needle_size)
{
	/* Like the standard library function memmem, but finds the last occurrence. */
	const gchar *p = memmem(haystack, haystack_size, needle, needle_size);
	const gchar *q;
	if (p == NULL)
		return NULL;
	for (;;) {
		p += needle_size;
		q = memmem(p, haystack + haystack_size - p, needle, needle_size);
		if (q == NULL)
			return p - needle_size;
		p = q;
	}
}

static gboolean
parse_signed_note(GBytes *signed_note,
		  GByteArray *parsed_public_key,
		  GBytes **original_text,
		  gchar *expected_key_name,
		  gchar *expected_key_hash,
		  GError **error)
{
#ifndef ENABLE_ED25519
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    __FUNCTION__ " requires Ed25519 support but it is not enabled");
	return FALSE;
#else

	gsize size = 0;
	const gchar *data = g_bytes_get_data(signed_note, &size);
	const gchar *signature_start = NULL;
	gsize signature_size = 0;
	const gchar *p, *end;
	g_autofree guchar *sig_str = NULL;
	g_autofree gchar *temp_sig = NULL;
	g_autofree gchar *key_name = NULL;
	gsize sig_size = 0;
	guchar *actual_key_hash = NULL;

	g_return_val_if_fail(original_text != NULL, FALSE);

	/* Must be valid UTF-8 */
	if (!g_utf8_validate(data, size, NULL)) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "signed note is not valid UTF-8");
		return FALSE;
	}

	/* Must not contain any control characters other than newline */
	for (p = data, end = data + size; p != end; p = g_utf8_next_char(p)) {
		gunichar u = g_utf8_get_char(p);
		if (u < 0x20 && u != '\n') {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "signed note contains invalid character");
			return FALSE;
		}
	}

	/* Get the signature block, which is delineated by two consecutive newline characters.
	 * Unfortunately we need to find the last occurrence. */
	signature_start = memrmem(data, size, "\n\n", 2);
	if (signature_start == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find any signature in signed note");
		return FALSE;
	}
	/* Include the first newline in the original text */
	*original_text = g_bytes_new(data, signature_start + 1 - data);
	/* Exclude both newlines in the signature block */
	signature_start += 2;
	signature_size = data + size - signature_start;
	if (signature_start[signature_size - 1] != '\n') {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "signature block must end with a endline");
		return FALSE;
	}

	/* Parse each signature. Note that we currently only support one, despite that in the
	 * canonical source the actual limit is (somewhat arbitrarily) 100. See
	 * https://cs.opensource.google/go/x/mod/+/refs/tags/v0.9.0:sumdb/note/note.go;l=568-571;drc=7c05a442b7c1d1a107879b4a090bb5a38d3774a1
	 */
	if (memchr(signature_start, '\n', signature_size) != signature_start + signature_size - 1) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "too many signatures in signature block");
		return FALSE;
	}
	signature_size -= 1;
	if (memcmp("\xe2\x80\x94 ", signature_start, 4) != 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "invalid signature prefix");
		return FALSE;
	}
	signature_start += 4;
	signature_size -= 4;
	p = memchr(signature_start, ' ', signature_size);
	if (p == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of key name");
		return FALSE;
	}
	if (p == signature_start) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "key name cannot be empty");
		return FALSE;
	}
	if (memchr(signature_start, '+', p - signature_start) != NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "key name cannot contain a plus sign");
		return FALSE;
	}
	key_name = g_strndup(signature_start, p - signature_start);
	if (strcmp(key_name, expected_key_name) != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unexpected key name; expecting %s but found %s",
			    expected_key_name,
			    key_name);
		return FALSE;
	}
	signature_size -= p - signature_start + 1;
	signature_start = p + 1;
	for (p = signature_start; p < signature_start + signature_size; ++p) {
		if (!g_ascii_isalnum(*p) && *p != '+' && *p != '/' && *p != '=') {
			g_set_error(
			    error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "incorrect base64 encoding for signature: invalid character 0x%02x",
			    (unsigned)*p);
			return FALSE;
		}
	}
	temp_sig = g_strndup(signature_start, signature_size);
	sig_str = g_base64_decode(temp_sig, &sig_size);

	/* The first four bytes are actually the key hash. */
	actual_key_hash = sig_str;
	if (memcmp(expected_key_hash, actual_key_hash, 4) != 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "actual key hash does not match expected key hash");
		return FALSE;
	}

	if (sig_size - 4 != ED25519_SIGNATURE_SIZE) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "invalid size for signature; should have size %d but has size %zu",
			    ED25519_SIGNATURE_SIZE,
			    sig_size - 4);
		return FALSE;
	}

	if (ed25519_sha512_verify(parsed_public_key->data,
				  g_bytes_get_size(*original_text),
				  g_bytes_get_data(*original_text, NULL),
				  sig_str + 4) == 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot verify Ed25519 signature");
		return FALSE;
	}
	return TRUE;
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

static GFile *
get_leaf_file(GFile *storage_dir, GBytes *leaf_hash)
{
	g_autoptr(GString) s = g_string_new(NULL);
	g_autoptr(GFile) d1 = g_file_get_child(storage_dir, "leaves");
	g_autoptr(GFile) d2 = NULL;
	g_autoptr(GFile) d3 = NULL;
	g_autoptr(GFile) d4 = NULL;
	gsize size = 0;
	const gchar *lh = g_bytes_get_data(leaf_hash, &size);

	g_return_val_if_fail(leaf_hash != NULL, NULL);
	g_return_val_if_fail(size >= 4, NULL);

	g_string_printf(s, "%02x", (unsigned)(guchar)*lh++);
	d2 = g_file_get_child(d1, s->str);
	g_string_printf(s, "%02x", (unsigned)(guchar)*lh++);
	d3 = g_file_get_child(d2, s->str);
	g_string_printf(s, "%02x", (unsigned)(guchar)*lh++);
	d4 = g_file_get_child(d3, s->str);
	g_string_printf(s, "%02x", (unsigned)(guchar)*lh++);
	for (size -= 4; size > 0; --size) {
		g_string_append_printf(s, "%02x", (unsigned)(guchar)*lh++);
	}
	return g_file_get_child(d4, s->str);
}

static GFile *
get_pending_leaf_file(GFile *storage_dir, GBytes *leaf_hash)
{
	g_autoptr(GString) s = g_string_new(NULL);
	g_autoptr(GFile) d1 = g_file_get_child(storage_dir, "leaves");
	g_autoptr(GFile) d2 = g_file_get_child(d1, "pending");
	gsize size = 0;
	const gchar *lh = g_bytes_get_data(leaf_hash, &size);

	g_return_val_if_fail(leaf_hash != NULL, NULL);
	g_return_val_if_fail(size >= 4, NULL);

	for (; size > 0; --size) {
		g_string_append_printf(s, "%02x", (unsigned)(guchar)*lh++);
	}
	return g_file_get_child(d2, s->str);
}

static GFile *
get_seq_path(GFile *storage_dir, guint64 seq)
{
	g_autoptr(GString) s = g_string_new(NULL);
	g_autoptr(GFile) d1 = g_file_get_child(storage_dir, "seq");
	g_autoptr(GFile) d2 = NULL;
	g_autoptr(GFile) d3 = NULL;
	g_autoptr(GFile) d4 = NULL;
	g_autoptr(GFile) d5 = NULL;

	g_string_printf(s, "%02x", (unsigned)(seq >> 32));
	d2 = g_file_get_child(d1, s->str);
	g_string_printf(s, "%02x", (unsigned)((seq >> 24) & 0xff));
	d3 = g_file_get_child(d2, s->str);
	g_string_printf(s, "%02x", (unsigned)((seq >> 16) & 0xff));
	d4 = g_file_get_child(d3, s->str);
	g_string_printf(s, "%02x", (unsigned)((seq >> 8) & 0xff));
	d5 = g_file_get_child(d4, s->str);
	g_string_printf(s, "%02x", (unsigned)(seq & 0xff));
	return g_file_get_child(d5, s->str);
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

static gboolean
parse_formatted_checkpoint(GBytes *formatted_checkpoint,
			   gchar **cp_origin,
			   guint64 *cp_size,
			   GBytes **cp_hash,
			   GBytes **cp_rest,
			   GError **error)
{
	/* This parses the content formatted by the above function `format_checkpoint`. */
	gsize size = 0;
	const gchar *data = g_bytes_get_data(formatted_checkpoint, &size);
	const gchar *end;
	gchar *end2;
	g_autofree gchar *temp_hash = NULL;
	guchar *hash_str = NULL;
	gsize hash_size = 0;

	g_return_val_if_fail(cp_origin != NULL, FALSE);
	g_return_val_if_fail(cp_size != NULL, FALSE);
	g_return_val_if_fail(cp_hash != NULL, FALSE);
	g_return_val_if_fail(cp_rest != NULL, FALSE);

	/* Origin */
	end = memchr(data, '\n', size);
	if (end == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of origin");
		return FALSE;
	}
	*cp_origin = g_strndup(data, end - data);

	/* Size */
	size -= end - data + 1;
	data = end + 1;
	end = memchr(data, '\n', size);
	if (end == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of size");
		return FALSE;
	}
	errno = 0;
	*cp_size = g_ascii_strtoull(data, &end2, 10);
	if (errno != 0 || end2 != end) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "failed to parse second line as number");
		return FALSE;
	}

	/* Base64-encoded hash */
	size -= end - data + 1;
	data = end + 1;
	end = memchr(data, '\n', size);
	if (end == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot find end of encoded hash");
		return FALSE;
	}
	for (gchar *p = data; p < end; ++p) {
		if (!g_ascii_isalnum(*p) && *p != '+' && *p != '/' && *p != '=') {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "incorrect base64 encoding for encoded hash");
			return FALSE;
		}
	}
	/* temp_hash required to ensure NULL termination */
	temp_hash = g_strndup(data, end - data);
	hash_str = g_base64_decode(temp_hash, &hash_size);
	*cp_hash = g_bytes_new_take(hash_str, hash_size);

	/* The rest */
	size -= end - data + 1;
	data = end + 1;
	*cp_rest = g_bytes_new(data, size);
	return TRUE;
}

static const guchar empty_root[32] = {
    /* echo -n ''|sha256sum|xxd -p -r|xxd -i */
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

/**
 * jcat_bt_integrate_init:
 * @storage_dir: (not nullable): the root directory for the storage
 * @private_key_contents: (not nullable): the contents of the private key
 * @cp_origin: (not nullable): the log origin string to use in produced checkpoint
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

/**
 * jcat_bt_fs_read_checkpoint:
 * @storage_dir: (not nullable): the root directory for the storage
 * @error: #GError, or %NULL
 *
 * Read the checkpoint from the on-disk storage directory.
 *
 * Since: 0.1.12
 **/
GBytes *
jcat_bt_fs_read_checkpoint(GFile *storage_dir, GError **error)
{
	g_autoptr(GFile) checkpoint_file = NULL;
	g_autofree gchar *checkpoint_file_path = NULL;

	checkpoint_file = g_file_get_child(storage_dir, "checkpoint");
	checkpoint_file_path = g_file_get_path(checkpoint_file);
	return jcat_get_contents_bytes(checkpoint_file_path, error);
}

/**
 * jcat_bt_parse_checkpoint:
 * @read_checkpoint: (not nullable): the checkpoint that was read from the filesystem
 * @public_key_file_content: (not nullable): the content of the public key file
 * @expected_origin: (not nullable): the expected origin
 * @cp_size: (not nullable) (out): the checkpoint size
 * @cp_hash: (not nullable) (out): the checkpoint hash
 * @error: #GError, or %NULL
 *
 * Parse a checkpoint that was read from the on-disk storage directory. It requires that a valid log
 *structure be found, the checkpoint be formatted correctly, and the log origin be expected. If not,
 *an empty checkpoint will be returned.
 *
 * Since: 0.1.12
 **/
gboolean
jcat_bt_parse_checkpoint(GBytes *read_checkpoint,
			 GBytes *public_key_file_content,
			 const gchar *expected_origin,
			 guint64 *cp_size,
			 GBytes **cp_hash,
			 GError **error)
{
	g_autoptr(GByteArray) parsed_public_key = NULL;
	g_autofree gchar *parsed_key_name = NULL;
	g_autofree gchar *parsed_key_hash = NULL;

	g_autoptr(GBytes) checkpoint_content = NULL;
	g_autofree gchar *key_name = NULL;

	g_autofree gchar *cp_origin = NULL;
	g_autoptr(GBytes) cp_rest = NULL;

	/* Parse the public key */
	if (!jcat_bt_parse_public_key(public_key_file_content,
				      &parsed_public_key,
				      &parsed_key_name,
				      &parsed_key_hash,
				      error)) {
		g_prefix_error(error, "cannot parse public key: ");
		return FALSE;
	}

	/* Verify the signatures using the provided public key */
	if (!parse_signed_note(read_checkpoint,
			       parsed_public_key,
			       &checkpoint_content,
			       parsed_key_name,
			       parsed_key_hash,
			       error)) {
		g_prefix_error(error, "cannot parse checkpoint as signed note: ");
		return FALSE;
	}

	/* Parse the checkpoint*/
	if (!parse_formatted_checkpoint(checkpoint_content,
					&cp_origin,
					cp_size,
					cp_hash,
					&cp_rest,
					error)) {
		g_prefix_error(error, "cannot parse checkpoint content: ");
		return FALSE;
	}

	if (strcmp(cp_origin, expected_origin) != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "unxpected origin; want %s got %s",
			    expected_origin,
			    cp_origin);
		return FALSE;
	}

	return TRUE;
}

/**
 * jcat_bt_fs_sequence:
 * @storage_dir: (not nullable): the directory where everything is stored
 * @next_seq: (not nullable) (inout): the next sequence number
 * @leaf_hash: (not nullable): the leaf hash
 * @content: (not nullable): the content of the entry
 * @error: #GError, or %NULL
 *
 * Assigns the given leaf entry to the next available sequence number.
 *
 * Since: 0.1.12
 **/
guint64
jcat_bt_fs_sequence(GFile *storage_dir,
		    guint64 *next_seq,
		    GBytes *leaf_hash,
		    GBytes *content,
		    GError **error)
{
	/* Check for the existence of the file */
	g_autoptr(GFile) leaf_file = NULL;
	g_autofree gchar *leaf_file_path = NULL;
	g_autoptr(GError) read_error = NULL;
	g_autoptr(GBytes) original_seq = NULL;
	g_autoptr(GError) delete_error = NULL;

	leaf_file = get_leaf_file(storage_dir, leaf_hash);
	leaf_file_path = g_file_get_path(leaf_file);

	/* First we attempt to read the file and see if it exists.  */
	original_seq = jcat_get_contents_bytes(leaf_file_path, &read_error);
	if (original_seq != NULL) {
		/* Parse and return the original sequence number. */

		/* Unfortunately GBytes does not guarantee NULL termination but g_ascii_strtoull
		 * requires it. */
		g_autofree gchar *original_seq_str =
		    g_strndup(g_bytes_get_data(original_seq, NULL), g_bytes_get_size(original_seq));
		guint64 ret;
		gchar *end;
		errno = 0;
		ret = g_ascii_strtoull(original_seq_str, &end, 16);
		if (errno != 0 || end != original_seq_str + g_bytes_get_size(original_seq)) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot parse sequence number in existing file %s",
				    leaf_file_path);
			return 0;
		}
		return ret;
	} else {
		g_autoptr(GFile) pending_leaf_file = NULL;
		g_autofree gchar *pending_leaf_file_path = NULL;

		g_debug("cannot read file %s; need to create it", leaf_file_path);
		pending_leaf_file = get_pending_leaf_file(storage_dir, leaf_hash);
		pending_leaf_file_path = g_file_get_path(pending_leaf_file);

		/* The original code takes care not to overwrite an existing file:
		 * https://github.com/google/trillian-examples/blob/2bad95478b7bf9c975a8656f3b1ab3c241bdae39/serverless/internal/storage/fs/fs.go#L134
		 * I don't think it necessary. We *can* overwrite files here. */
		if (!jcat_set_contents_bytes(pending_leaf_file_path, content, error)) {
			g_prefix_error(error,
				       "cannot write to pending leaf file %s",
				       pending_leaf_file_path);
			return 0;
		}

		for (;;) {
			guint64 seq = *next_seq;
			g_autoptr(GFile) seq_file = get_seq_path(storage_dir, seq);
			g_autofree gchar *seq_file_path = g_file_get_path(seq_file);
			g_autoptr(GFile) seq_file_parent = g_file_get_parent(seq_file);
			gboolean ret;

			if (!g_file_make_directory_with_parents(seq_file_parent, NULL, error)) {
				g_file_delete(pending_leaf_file, NULL, &delete_error);
				g_prefix_error(
				    error,
				    "failed to create parent directory for seq file %s: ",
				    seq_file_path);
				return 0;
			}

			/* The original code makes a hard link:
			 * https://github.com/google/trillian-examples/blob/2bad95478b7bf9c975a8656f3b1ab3c241bdae39/serverless/internal/storage/fs/fs.go#L153
			 * Here we just write the file again, taking care not to overwrite any
			 * existing file. */
			ret = g_file_copy(pending_leaf_file,
					  seq_file,
					  G_FILE_COPY_NONE, /* Do not use G_FILE_COPY_OVERWRITE */
					  NULL,
					  NULL,
					  NULL,
					  error);
			if (!ret) {
				/* Distinguish between file-exist errors and all other errors. */
				if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_EXISTS)) {
					/* Try the next sequence number. */
					++*next_seq;
					g_clear_error(error);
					continue;
				} else {
					g_file_delete(pending_leaf_file, NULL, &delete_error);
					g_prefix_error(error,
						       "failed to create seq file %s: ",
						       seq_file_path);
					return 0;
				}
			} else {
				/* Now we can write to the leaf file. */
				GString *seq_str = g_string_new(NULL);
				g_autoptr(GBytes) seq_bytes = NULL;
				g_string_printf(seq_str, "%llx", (unsigned long long)seq);
				seq_bytes = g_string_free_to_bytes(seq_str);
				if (!jcat_set_contents_bytes(leaf_file_path, seq_bytes, error)) {
					/* We probably shouldn't overwrite here. */
					g_file_delete(pending_leaf_file, NULL, &delete_error);
					g_prefix_error(error,
						       "failed to create leaf file %s",
						       leaf_file_path);
					return 0;
				}
				g_file_delete(pending_leaf_file, NULL, &delete_error);
				return seq;
			}
		}
	}
}
