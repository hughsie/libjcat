#pragma once

#include <json-glib/json-glib.h>

/* count number of 1's set */
guint
jcat_bits_ones_count64(guint64 val);

/* count number of trailing zeros */
guint
jcat_bits_trailing_zeros64(guint64 val);

/* minimum number of bits required to represent number */
guint
jcat_bits_bit_length64(guint64 val);

guint
jcat_inner_proof_size(guint64 index, guint64 size);

void
_g_set_byte_array(GByteArray **buf, GByteArray *buf_new);

gboolean
fu_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error);

gchar *
jcat_hex_encode_string(GByteArray *buf);

GPtrArray *
jcat_byte_arrays_slice_left(GPtrArray *src, guint pos, GError **error);

GPtrArray *
jcat_byte_arrays_slice_right(GPtrArray *src, guint pos, GError **error);
