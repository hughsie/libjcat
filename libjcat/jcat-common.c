/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include <config.h>

#include <errno.h>

#include "jcat-common-private.h"

/* private */
gboolean
jcat_mkdir_parent (const gchar *filename, GError **error)
{
	g_autofree gchar *parent = NULL;

	parent = g_path_get_dirname (filename);
	g_debug ("creating path %s", parent);
	if (g_mkdir_with_parents (parent, 0755) == -1) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "Failed to create '%s': %s",
			     parent, g_strerror (errno));
		return FALSE;
	}
	return TRUE;
}

/* private */
gboolean
jcat_set_contents_bytes (const gchar *filename, GBytes *bytes, GError **error)
{
	const gchar *data;
	gsize size;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFile) file_parent = NULL;

	file = g_file_new_for_path (filename);
	file_parent = g_file_get_parent (file);
	if (!g_file_query_exists (file_parent, NULL)) {
		if (!g_file_make_directory_with_parents (file_parent, NULL, error))
			return FALSE;
	}
	data = g_bytes_get_data (bytes, &size);
	g_debug ("writing %s with %" G_GSIZE_FORMAT " bytes", filename, size);
	return g_file_set_contents (filename, data, size, error);
}

/* private */
GBytes *
jcat_get_contents_bytes (const gchar *filename, GError **error)
{
	gchar *data = NULL;
	gsize len = 0;
	if (!g_file_get_contents (filename, &data, &len, error))
		return NULL;
	g_debug ("reading %s with %" G_GSIZE_FORMAT " bytes", filename, len);
	return g_bytes_new_take (data, len);
}

static gsize
jcat_strwidth (const gchar *text)
{
	const gchar *p = text;
	gsize width = 0;
	while (*p) {
		gunichar c = g_utf8_get_char (p);
		if (g_unichar_iswide (c))
			width += 2;
		else if (!g_unichar_iszerowidth (c))
			width += 1;
		p = g_utf8_next_char (p);
	}
	return width;
}

/* private */
void
jcat_string_append_kv (GString *str, guint idt, const gchar *key, const gchar *value)
{
	const guint align = 25;
	gsize keysz;

	g_return_if_fail (idt * 2 < align);

	/* ignore */
	if (key == NULL)
		return;
	for (gsize i = 0; i < idt; i++)
		g_string_append (str, "  ");
	if (key[0] != '\0') {
		g_string_append_printf (str, "%s:", key);
		keysz = (idt * 2) + jcat_strwidth (key) + 1;
	} else {
		keysz = idt * 2;
	}
	if (value != NULL) {
		g_auto(GStrv) split = NULL;
		split = g_strsplit (value, "\n", -1);
		for (guint i = 0; split[i] != NULL; i++) {
			if (i == 0) {
				for (gsize j = keysz; j < align; j++)
					g_string_append (str, " ");
			} else {
				for (gsize j = 0; j < align; j++)
					g_string_append (str, " ");
			}
			g_string_append (str, split[i]);
			g_string_append (str, "\n");
		}
	} else {
		g_string_append (str, "\n");
	}
}
