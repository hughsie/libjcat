/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#include "jcat-blob.h"

#define JCAT_TYPE_ITEM (jcat_item_get_type ())

G_DECLARE_DERIVABLE_TYPE (JcatItem, jcat_item, JCAT, ITEM, GObject)

struct _JcatItemClass
{
	GObjectClass		 parent_class;
	gpointer		 padding[15];
};

JcatItem	*jcat_item_new				(const gchar	*id);
gchar		*jcat_item_to_string 			(JcatItem	*self);
GPtrArray	*jcat_item_get_blobs			(JcatItem	*self);
GPtrArray	*jcat_item_get_blobs_by_kind		(JcatItem	*self,
							 JcatBlobKind	 kind);
void		 jcat_item_add_blob			(JcatItem	*self,
							 JcatBlob	*blob);
const gchar	*jcat_item_get_id			(JcatItem	*self);
void		 jcat_item_add_alias_id			(JcatItem	*self,
							 const gchar	*id);
void		 jcat_item_remove_alias_id		(JcatItem	*self,
							 const gchar	*id);
GPtrArray	*jcat_item_get_alias_ids		(JcatItem	*self);
