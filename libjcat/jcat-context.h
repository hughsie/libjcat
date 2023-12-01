/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#include "jcat-blob.h"
#include "jcat-engine.h"
#include "jcat-item.h"

#define JCAT_TYPE_CONTEXT jcat_context_get_type()

G_DECLARE_DERIVABLE_TYPE(JcatContext, jcat_context, JCAT, CONTEXT, GObject)

struct _JcatContextClass {
	GObjectClass parent_class;
	gpointer padding[15];
};

JcatContext *
jcat_context_new(void);
void
jcat_context_add_public_key(JcatContext *self, const gchar *filename) G_GNUC_NON_NULL(1, 2);
void
jcat_context_add_public_keys(JcatContext *self, const gchar *path) G_GNUC_NON_NULL(1, 2);
JcatEngine *
jcat_context_get_engine(JcatContext *self, JcatBlobKind kind, GError **error) G_GNUC_NON_NULL(1);
void
jcat_context_set_keyring_path(JcatContext *self, const gchar *path) G_GNUC_NON_NULL(1);
const gchar *
jcat_context_get_keyring_path(JcatContext *self) G_GNUC_NON_NULL(1);
JcatResult *
jcat_context_verify_blob(JcatContext *self,
			 GBytes *data,
			 JcatBlob *blob,
			 JcatVerifyFlags flags,
			 GError **error) G_GNUC_NON_NULL(1, 2, 3);
GPtrArray *
jcat_context_verify_item(JcatContext *self,
			 GBytes *data,
			 JcatItem *item,
			 JcatVerifyFlags flags,
			 GError **error) G_GNUC_NON_NULL(1, 2, 3);
void
jcat_context_blob_kind_allow(JcatContext *self, JcatBlobKind kind) G_GNUC_NON_NULL(1);
void
jcat_context_blob_kind_disallow(JcatContext *self, JcatBlobKind kind) G_GNUC_NON_NULL(1);
