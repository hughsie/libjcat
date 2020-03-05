/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>
#include <gio/gio.h>

#include "jcat-blob.h"
#include "jcat-common.h"
#include "jcat-result.h"

#define JCAT_TYPE_ENGINE (jcat_engine_get_type ())
G_DECLARE_DERIVABLE_TYPE (JcatEngine, jcat_engine, JCAT, ENGINE, GObject)

struct _JcatEngineClass
{
	GObjectClass		 parent_class;
	gboolean		 (*setup)		(JcatEngine	*self,
							 GError		**error);
	gboolean		 (*add_public_key)	(JcatEngine	*self,
							 const gchar	*filename,
							 GError		**error);
	JcatResult		*(*verify_data)		(JcatEngine	*self,
							 GBytes		*payload,
							 GBytes		*payload_signature,
							 JcatVerifyFlags flags,
							 GError		**error);
	JcatBlob		*(*sign_data)		(JcatEngine	*self,
							 GBytes		*payload,
							 JcatSignFlags flags,
							 GError		**error);
	gpointer		 padding[11];
};

JcatResult	*jcat_engine_verify			(JcatEngine	*self,
							 GBytes		*blob,
							 GBytes		*blob_signature,
							 JcatVerifyFlags flags,
							 GError		**error);
JcatBlob	*jcat_engine_sign			(JcatEngine	*self,
							 GBytes		*blob,
							 JcatSignFlags flags,
							 GError		**error);
