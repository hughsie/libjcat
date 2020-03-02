/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-common.h"
#include "jcat-item.h"

#include <json-glib/json-glib.h>

JcatItem	*jcat_item_import			(JsonObject	*obj,
							 JcatImportFlags flags,
							 GError		**error);
void		 jcat_item_export			(JcatItem 	*self,
							 JcatExportFlags flags,
							 JsonBuilder	*builder);
void		 jcat_item_add_string			(JcatItem	*self,
							 guint		 idt,
							 GString	*str);
