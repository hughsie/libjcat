/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-blob.h"
#include "jcat-common.h"

#include <json-glib/json-glib.h>

JcatBlob	*jcat_blob_import			(JsonObject	*obj,
							 JcatImportFlags flags,
							 GError		**error);
void		 jcat_blob_export			(JcatBlob 	*self,
							 JcatExportFlags flags,
							 JsonBuilder	*builder);
void		 jcat_blob_add_string			(JcatBlob	*self,
							 guint		 idt,
							 GString	*str);
