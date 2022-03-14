/*
 * Copyright (C) 2023 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>
#include <glib-object.h>

gboolean
jcat_bt_generate_key_pair(const gchar *keyname,
			  GBytes **public_key,
			  GBytes **private_key,
			  GError **error);

gboolean
jcat_bt_parse_private_key(GBytes *private_key_file_content,
			  GByteArray **parsed_private_key,
			  GByteArray **parsed_public_key,
			  gchar **parsed_key_name,
			  gchar **parsed_key_hash,
			  GError **error);

gboolean
jcat_bt_parse_public_key(GBytes *public_key_file_content,
			 GByteArray **parsed_public_key,
			 gchar **parsed_key_name,
			 gchar **parsed_key_hash,
			 GError **error);

gboolean
jcat_bt_integrate_init(GFile *storage_dir,
		       GBytes *private_key_contents,
		       const gchar *cp_origin,
		       GError **error);

GBytes *
jcat_bt_fs_read_checkpoint(GFile *storage_dir, GError **error);

gboolean
jcat_bt_parse_checkpoint(GBytes *read_checkpoint,
			 GBytes *public_key_file_content,
			 const gchar *expected_origin,
			 guint64 *cp_size,
			 GBytes **cp_hash,
			 GError **error);

gboolean
jcat_bt_fs_sequence(GFile *storage_dir,
		    guint64 *next_seq,
		    GBytes *leaf_hash,
		    GBytes *content,
		    guint64 *assigned_seq,
		    GError **error);
