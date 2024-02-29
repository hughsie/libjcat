/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gio/gio.h>
#include <glib/gstdio.h>

#include "jcat-common-private.h"

/* private */
gboolean
jcat_mkdir_parent(const gchar *filename, GError **error)
{
	g_autoptr(GFile) file = g_file_new_for_path(filename);
	g_autoptr(GFile) file_parent = g_file_get_parent(file);
	if (g_file_query_exists(file_parent, NULL))
		return TRUE;
	return g_file_make_directory_with_parents(file_parent, NULL, error);
}

/* private */
gboolean
jcat_set_contents_bytes(const gchar *filename, GBytes *bytes, GError **error)
{
	const gchar *data;
	gsize size;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFile) file_parent = NULL;

	file = g_file_new_for_path(filename);
	file_parent = g_file_get_parent(file);
	if (!g_file_query_exists(file_parent, NULL)) {
		if (!g_file_make_directory_with_parents(file_parent, NULL, error))
			return FALSE;
	}
	data = g_bytes_get_data(bytes, &size);
	g_debug("writing %s with %" G_GSIZE_FORMAT " bytes", filename, size);
	return g_file_set_contents(filename, data, size, error);
}

/* private */
GBytes *
jcat_get_contents_bytes(const gchar *filename, GError **error)
{
	gchar *data = NULL;
	gsize len = 0;
	if (!g_file_get_contents(filename, &data, &len, error))
		return NULL;
	g_debug("reading %s with %" G_GSIZE_FORMAT " bytes", filename, len);
	return g_bytes_new_take(data, len);
}

/* private */
GByteArray *
jcat_get_contents_byte_array(const gchar *filename, GError **error)
{
	gchar *data = NULL;
	gsize len = 0;
	if (!g_file_get_contents(filename, &data, &len, error))
		return NULL;
	g_debug("reading %s with %" G_GSIZE_FORMAT " bytes", filename, len);
	return g_byte_array_new_take(data, len);
}

static gsize
jcat_strwidth(const gchar *text)
{
	const gchar *p = text;
	gsize width = 0;
	while (*p) {
		gunichar c = g_utf8_get_char(p);
		if (g_unichar_iswide(c))
			width += 2;
		else if (!g_unichar_iszerowidth(c))
			width += 1;
		p = g_utf8_next_char(p);
	}
	return width;
}

/* private */
void
jcat_string_append_kv(GString *str, guint idt, const gchar *key, const gchar *value)
{
	const guint align = 25;
	gsize keysz;

	g_return_if_fail(idt * 2 < align);

	/* ignore */
	if (key == NULL)
		return;
	for (gsize i = 0; i < idt; i++)
		g_string_append(str, "  ");
	if (key[0] != '\0') {
		g_string_append_printf(str, "%s:", key);
		keysz = (idt * 2) + jcat_strwidth(key) + 1;
	} else {
		keysz = idt * 2;
	}
	if (value != NULL) {
		g_auto(GStrv) split = NULL;
		split = g_strsplit(value, "\n", -1);
		for (guint i = 0; split[i] != NULL; i++) {
			if (i == 0) {
				for (gsize j = keysz; j < align; j++)
					g_string_append(str, " ");
			} else {
				for (gsize j = 0; j < align; j++)
					g_string_append(str, " ");
			}
			g_string_append(str, split[i]);
			g_string_append(str, "\n");
		}
	} else {
		g_string_append(str, "\n");
	}
}

/* private */
void
jcat_string_append_kx(GString *str, guint idt, const gchar *key, guint value)
{
	g_autofree gchar *tmp = g_strdup_printf("0x%x", value);
	jcat_string_append_kv(str, idt, key, tmp);
}

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/**
 * jcat_bits_ones_count64:
 * @val: input
 *
 * Count the number of 1's set.
 *
 * Returns: integer
 *
 * Since: 0.2.0
 **/
guint
jcat_bits_ones_count64(guint64 val)
{
#if __has_builtin(__builtin_popcountll)
	return __builtin_popcountll(val);
#else
	guint c = 0;
	for (guint i = 0; i < 64; i++) {
		if (val & ((guint64)0b1 << i))
			c += 1;
	}
	return c;
#endif
}

/**
 * jcat_bits_trailing_zeros64:
 * @val: input
 *
 * Count the number of trailing zero bits.
 *
 * Returns: integer
 *
 * Since: 0.2.0
 **/
guint
jcat_bits_trailing_zeros64(guint64 val)
{
#if __has_builtin(__builtin_ctzll)
	if (val == 0)
		return 64;
	return __builtin_ctzll(val);
#else
	for (guint i = 0; i < 64; i++) {
		if (val & ((guint64)0b1 << i))
			return i;
	}
	return 64;
#endif
}

/**
 * jcat_bits_length64:
 * @val: input
 *
 * Find the minimum number of bits required to represent a number.
 *
 * Returns: integer
 *
 * Since: 0.2.0
 **/
guint
jcat_bits_length64(guint64 val)
{
#if __has_builtin(__builtin_clzll)
	if (val == 0)
		return 0;
	return 64 - __builtin_clzll(val);
#else
	for (guint i = 0; i < 64; i++) {
		if (((guint64)1 << i) > val)
			return i;
	}
	return 64;
#endif
}

/**
 * jcat_inner_proof_size:
 * @index: input
 * @size: input
 *
 * Find the inner proof size.
 *
 * Returns: integer
 *
 * Since: 0.2.0
 **/
guint
jcat_inner_proof_size(guint64 index, guint64 size)
{
	return jcat_bits_length64(index ^ (size - 1));
}

/**
 * jcat_set_byte_array:
 * @buf: (not nullable) (out): the buffer
 * @buf_new: (not nullable): the new buffer contents
 *
 * Assign a #GByteArray to another #GByteArray.
 *
 * Since: 0.2.0
 **/
void
jcat_set_byte_array(GByteArray **buf, GByteArray *buf_new)
{
	if (buf_new == *buf)
		return;
	if (*buf != NULL)
		g_byte_array_unref(*buf);
	*buf = g_byte_array_ref(buf_new);
}

/**
 * jcat_set_bytes:
 * @buf: (not nullable) (out): the buffer
 * @buf_new: (not nullable): the new buffer contents
 *
 * Assign a #GBytes to another #GBytes.
 *
 * Since: 0.2.0
 **/
void
jcat_set_bytes(GBytes **buf, GBytes *buf_new)
{
	if (buf_new == *buf)
		return;
	if (*buf != NULL)
		g_bytes_unref(*buf);
	*buf = g_bytes_ref(buf_new);
}

/**
 * jcat_byte_array_compare:
 * @buf1: (not nullable): the first buffer
 * @buf2: (not nullable): the second buffer
 * @error: (nullable): #GError, or %NULL
 *
 * Compare two instances of #GByteArray
 *
 * Returns: Boolean indicating whether they are equal
 *
 * Since: 0.2.0
 **/
gboolean
jcat_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error)
{
	g_return_val_if_fail(buf1 != NULL, FALSE);
	g_return_val_if_fail(buf2 != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* not the same length */
	if (buf1->len != buf2->len) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "got %u bytes, expected %u",
			    buf1->len,
			    buf2->len);
		return FALSE;
	}

	/* NULL check */
	if (buf1->len > 0 && (buf1->data == NULL || buf2->data == NULL)) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "buf1 or buf2 NULL with non-zero size %u %u",
			    buf1->len,
			    buf2->len);
		return FALSE;
	}

	/* check matches */
	for (guint i = 0x0; i < buf1->len; i++) {
		if (buf1->data[i] != buf2->data[i]) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "got 0x%02x, expected 0x%02x @ 0x%04x",
				    buf1->data[i],
				    buf2->data[i],
				    i);
			return FALSE;
		}
	}

	/* success */
	return TRUE;
}

/**
 * jcat_hex_encode_string:
 * @buf: (not nullable): the buffer
 *
 * Hex encode.
 *
 * Returns: (transfer full): the hex-encoded buffer
 *
 * Since: 0.2.0
 **/
gchar *
jcat_hex_encode_string(GByteArray *buf)
{
	GString *str = g_string_new(NULL);
	for (guint i = 0; i < buf->len; i++)
		g_string_append_printf(str, "%02x", buf->data[i]);
	return g_string_free(str, FALSE);
}

/**
 * jcat_byte_arrays_slice_left:
 * @src: (element-type GByteArray) (not nullable): the source array
 * @idx: integer
 * @error: (nullable): #GError, or %NULL
 *
 * Slices a #GPtrArray of #GByteArray from the left.
 *
 * Returns: (element-type GByteArray) (transfer container): returned array
 *
 * Since: 0.2.0
 **/
GPtrArray *
jcat_byte_arrays_slice_left(GPtrArray *src, guint idx, GError **error)
{
	g_autoptr(GPtrArray) dst =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);

	g_return_val_if_fail(src != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	/* sanity check; but note that idx == src->len is valid */
	if (idx > src->len) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "idx %u of %u", idx, src->len);
		return NULL;
	}

	/* copy from 0 to idx, non-inclusive */
	for (guint i = 0; i < src->len && i < idx; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return g_steal_pointer(&dst);
}

GPtrArray *
jcat_byte_arrays_slice_right(GPtrArray *src, guint idx, GError **error)
{
	g_autoptr(GPtrArray) dst =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);

	/* sanity check; but note that idx == src->len is valid */
	if (idx > src->len) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "idx %u of %u", idx, src->len);
		return NULL;
	}

	/* copy from 0 to idx, non-inclusive */
	for (guint i = idx; i < src->len; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return g_steal_pointer(&dst);
}
