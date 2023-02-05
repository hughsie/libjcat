#include "jcat-proof-bits-private.h"

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/* count number of 1's set */
guint
bits_OnesCount64(guint64 val)
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

/* count number of trailing zeros */
guint
bits_TrailingZeros64(guint64 val)
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

/* minimum number of bits required to represent number */
guint
bits_Len64(guint64 val)
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

guint
innerProofSize(guint64 index, guint64 size)
{
	return bits_Len64(index ^ (size - 1));
}

void
_g_set_byte_array(GByteArray **buf, GByteArray *buf_new)
{
	if (buf_new == *buf)
		return;
	g_byte_array_unref(*buf);
	*buf = g_byte_array_ref(buf_new);
}

static gboolean
fu_common_bytes_compare_raw(const guint8 *buf1,
			    gsize bufsz1,
			    const guint8 *buf2,
			    gsize bufsz2,
			    GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* not the same length */
	if (bufsz1 != bufsz2) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "got %" G_GSIZE_FORMAT " bytes, expected "
			    "%" G_GSIZE_FORMAT,
			    bufsz1,
			    bufsz2);
		return FALSE;
	}

	/* NULL check */
	if (bufsz1 > 0 && (buf1 == NULL || buf2 == NULL)) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "buf1 or buf2 NULL with non-zero size %" G_GSIZE_FORMAT
			    " %" G_GSIZE_FORMAT,
			    bufsz1,
			    bufsz2);
		return FALSE;
	}

	/* check matches */
	for (guint i = 0x0; i < bufsz1; i++) {
		if (buf1[i] != buf2[i]) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "got 0x%02x, expected 0x%02x @ 0x%04x",
				    buf1[i],
				    buf2[i],
				    i);
			return FALSE;
		}
	}

	/* success */
	return TRUE;
}

gboolean
fu_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error)
{
	g_return_val_if_fail(buf1 != NULL, FALSE);
	g_return_val_if_fail(buf2 != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	return fu_common_bytes_compare_raw(buf1->data, buf1->len, buf2->data, buf2->len, error);
}

gchar *
jcat_rfc6962_decode_string(GByteArray *buf)
{
	GString *str = g_string_new(NULL);
	for (guint i = 0; i < buf->len; i++)
		g_string_append_printf(str, "%02x", buf->data[i]);
	return g_string_free(str, FALSE);
}

GPtrArray *
jcat_rfc6962_proof_slice_left(GPtrArray *src, guint pos, GError **error)
{
	GPtrArray *dst;

	/* sanity check; but note that pos == src->len is valid */
	if (pos > src->len) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "jcat_rfc6962_proof_slice_left: pos %u of %u",
			    pos,
			    src->len);
		return NULL;
	}

	/* copy from 0 to pos, non-inclusive */
	dst = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (guint i = 0; i < src->len && i < pos; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return dst;
}

GPtrArray *
jcat_rfc6962_proof_slice_right(GPtrArray *src, guint pos, GError **error)
{
	GPtrArray *dst;

	/* sanity check; but note that pos == src->len is valid */
	if (pos > src->len) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "jcat_rfc6962_proof_slice_right: pos %u of %u",
			    pos,
			    src->len);
		return NULL;
	}

	/* copy from 0 to pos, non-inclusive */
	dst = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (guint i = pos; i < src->len; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return dst;
}
