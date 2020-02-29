/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>

#include "jcat-common.h"

gboolean	 jcat_mkdir_parent		(const gchar	*filename,
						 GError		**error);
gboolean	 jcat_set_contents_bytes	(const gchar	*filename,
						 GBytes		*bytes,
						 GError		**error);
GBytes		*jcat_get_contents_bytes	(const gchar	*filename,
						 GError		**error);
void		 jcat_string_append_kv		(GString	*str,
						 guint		 idt,
						 const gchar 	*key,
						 const gchar	*value);
