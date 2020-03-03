/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#include "jcat-blob.h"
#include "jcat-item.h"
#include "jcat-engine.h"

#define JCAT_TYPE_CONTEXT jcat_context_get_type()

G_DECLARE_DERIVABLE_TYPE(JcatContext, jcat_context, JCAT, CONTEXT, GObject)

struct _JcatContextClass
{
	GObjectClass		 parent_class;
	gpointer		 padding[15];
};

JcatContext	*jcat_context_new			(void);
void		 jcat_context_add_public_keys		(JcatContext	*self,
							 const gchar	*path);
JcatEngine	*jcat_context_get_engine		(JcatContext	*self,
							 JcatBlobKind	 kind,
							 GError		**error);
void		 jcat_context_set_localstatedir		(JcatContext	*self,
							 const gchar	*path);
const gchar	*jcat_context_get_localstatedir		(JcatContext	*self);
JcatResult	*jcat_context_verify_blob		(JcatContext	*self,
							 GBytes		*data,
							 JcatBlob	*blob,
							 JcatVerifyFlags flags,
							 GError		**error);
GPtrArray	*jcat_context_verify_item		(JcatContext	*self,
							 GBytes		*data,
							 JcatItem	*item,
							 JcatVerifyFlags flags,
							 GError		**error);
JcatBlob	*jcat_context_sign			(JcatContext	*self,
							 JcatBlobKind	 kind,
							 GBytes		*data,
							 JcatSignFlags flags,
							 GError		**error);
