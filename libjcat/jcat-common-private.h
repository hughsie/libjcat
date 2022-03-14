/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>

#include "jcat-common.h"
#include "jcat-compile.h"

gboolean
jcat_mkdir_parent(const gchar *filename, GError **error) G_GNUC_NON_NULL(1);
gboolean
jcat_set_contents_bytes(const gchar *filename, GBytes *bytes, GError **error) G_GNUC_NON_NULL(1, 2);
GBytes *
jcat_get_contents_bytes(const gchar *filename, GError **error) G_GNUC_NON_NULL(1);
void
jcat_string_append_kv(GString *str, guint idt, const gchar *key, const gchar *value)
    G_GNUC_NON_NULL(1);
void
jcat_string_append_kx(GString *str, guint idt, const gchar *key, guint value) G_GNUC_NON_NULL(1);
guint
jcat_bits_ones_count64(guint64 val);
guint
jcat_bits_trailing_zeros64(guint64 val);
guint
jcat_bits_length64(guint64 val);
guint
jcat_inner_proof_size(guint64 index, guint64 size);
void
jcat_set_byte_array(GByteArray **buf, GByteArray *buf_new);
void
jcat_set_bytes(GBytes **buf, GBytes *buf_new);
gboolean
jcat_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error);
gchar *
jcat_hex_encode_string(GByteArray *buf);
GPtrArray *
jcat_byte_arrays_slice_left(GPtrArray *src, guint idx, GError **error);
GPtrArray *
jcat_byte_arrays_slice_right(GPtrArray *src, guint idx, GError **error);
