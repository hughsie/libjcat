/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#include "jcat-blob.h"

#define JCAT_TYPE_ITEM (jcat_item_get_type())

G_DECLARE_DERIVABLE_TYPE(JcatItem, jcat_item, JCAT, ITEM, GObject)

struct _JcatItemClass {
	GObjectClass parent_class;
	gpointer padding[15];
};

JcatItem *
jcat_item_new(const gchar *id);
gchar *
jcat_item_to_string(JcatItem *self) G_GNUC_NON_NULL(1);
GPtrArray *
jcat_item_get_blobs(JcatItem *self) G_GNUC_NON_NULL(1);
GPtrArray *
jcat_item_get_blobs_by_kind(JcatItem *self, JcatBlobKind kind) G_GNUC_NON_NULL(1);
void
jcat_item_add_blob(JcatItem *self, JcatBlob *blob) G_GNUC_NON_NULL(1, 2);
const gchar *
jcat_item_get_id(JcatItem *self) G_GNUC_NON_NULL(1);
void
jcat_item_add_alias_id(JcatItem *self, const gchar *id) G_GNUC_NON_NULL(1, 2);
void
jcat_item_remove_alias_id(JcatItem *self, const gchar *id) G_GNUC_NON_NULL(1, 2);
GPtrArray *
jcat_item_get_alias_ids(JcatItem *self) G_GNUC_NON_NULL(1);
