/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <json-glib/json-glib.h>

guint
jcat_bits_ones_count64(guint64 val);

guint
jcat_bits_trailing_zeros64(guint64 val);

guint
jcat_bits_bit_length64(guint64 val);

guint
jcat_inner_proof_size(guint64 index, guint64 size);

void
_g_set_byte_array(GByteArray **buf, GByteArray *buf_new);

gboolean
jcat_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error);

gchar *
jcat_hex_encode_string(GByteArray *buf);

GPtrArray *
jcat_byte_arrays_slice_left(GPtrArray *src, guint pos, GError **error);

GPtrArray *
jcat_byte_arrays_slice_right(GPtrArray *src, guint pos, GError **error);
