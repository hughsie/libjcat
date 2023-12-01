/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <json-glib/json-glib.h>

#include "jcat-blob.h"
#include "jcat-common.h"

JcatBlob *
jcat_blob_import(JsonObject *obj, JcatImportFlags flags, GError **error) G_GNUC_NON_NULL(1);
void
jcat_blob_export(JcatBlob *self, JcatExportFlags flags, JsonBuilder *builder) G_GNUC_NON_NULL(1, 3);
void
jcat_blob_add_string(JcatBlob *self, guint idt, GString *str) G_GNUC_NON_NULL(1, 3);
