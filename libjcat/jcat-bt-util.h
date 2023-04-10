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
jcat_bt_integrate_init(GFile *storage_dir,
		       GBytes *private_key_contents,
		       const gchar *cp_origin,
		       GError **error);
