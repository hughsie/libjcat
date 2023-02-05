#pragma once

#include <json-glib/json-glib.h>

/* count number of 1's set */
guint
bits_OnesCount64(guint64 val);

/* count number of trailing zeros */
guint
bits_TrailingZeros64(guint64 val);

/* minimum number of bits required to represent number */
guint
bits_Len64(guint64 val);

guint
innerProofSize(guint64 index, guint64 size);

void
_g_set_byte_array(GByteArray **buf, GByteArray *buf_new);

gboolean
fu_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error);

gchar *
jcat_rfc6962_decode_string(GByteArray *buf);

GPtrArray *
jcat_rfc6962_proof_slice_left(GPtrArray *src, guint pos, GError **error);

GPtrArray *
jcat_rfc6962_proof_slice_right(GPtrArray *src, guint pos, GError **error);
