/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gio/gio.h>
#include <glib/gstdio.h>

#include "fu-jcat-common.h"

/* private */
gboolean
fu_bytes_set_contents_full(const gchar *filename, GBytes *bytes, gint mode, GError **error)
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
#if GLIB_CHECK_VERSION(2, 66, 0)
	return g_file_set_contents_full(filename,
					data,
					size,
					G_FILE_SET_CONTENTS_CONSISTENT,
					mode,
					error);
#else
	return g_file_set_contents(filename, data, size, error);
#endif
}
