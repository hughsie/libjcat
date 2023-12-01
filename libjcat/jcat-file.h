/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>

#include "jcat-common.h"
#include "jcat-item.h"

#define JCAT_TYPE_FILE (jcat_file_get_type())

G_DECLARE_DERIVABLE_TYPE(JcatFile, jcat_file, JCAT, FILE, GObject)

struct _JcatFileClass {
	GObjectClass parent_class;
	gpointer padding[15];
};

JcatFile *
jcat_file_new(void);
gchar *
jcat_file_to_string(JcatFile *self) G_GNUC_NON_NULL(1);
gboolean
jcat_file_import_stream(JcatFile *self,
			GInputStream *istream,
			JcatImportFlags flags,
			GCancellable *cancellable,
			GError **error) G_GNUC_NON_NULL(1, 2);
gboolean
jcat_file_import_file(JcatFile *self,
		      GFile *gfile,
		      JcatImportFlags flags,
		      GCancellable *cancellable,
		      GError **error) G_GNUC_NON_NULL(1, 2);
gboolean
jcat_file_import_json(JcatFile *self, const gchar *json, JcatImportFlags flags, GError **error)
    G_GNUC_NON_NULL(1, 2);
gboolean
jcat_file_export_stream(JcatFile *self,
			GOutputStream *ostream,
			JcatExportFlags flags,
			GCancellable *cancellable,
			GError **error) G_GNUC_NON_NULL(1, 2);
gboolean
jcat_file_export_file(JcatFile *self,
		      GFile *gfile,
		      JcatExportFlags flags,
		      GCancellable *cancellable,
		      GError **error) G_GNUC_NON_NULL(1, 2);
gchar *
jcat_file_export_json(JcatFile *self, JcatExportFlags flags, GError **error) G_GNUC_NON_NULL(1);
GPtrArray *
jcat_file_get_items(JcatFile *self) G_GNUC_NON_NULL(1);
JcatItem *
jcat_file_get_item_by_id(JcatFile *self, const gchar *id, GError **error) G_GNUC_NON_NULL(1, 2);
JcatItem *
jcat_file_get_item_default(JcatFile *self, GError **error) G_GNUC_NON_NULL(1);
void
jcat_file_add_item(JcatFile *self, JcatItem *item) G_GNUC_NON_NULL(1);
guint32
jcat_file_get_version_major(JcatFile *self) G_GNUC_NON_NULL(1);
guint32
jcat_file_get_version_minor(JcatFile *self) G_GNUC_NON_NULL(1);
