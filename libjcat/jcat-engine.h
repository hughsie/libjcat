/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>
#include <glib-object.h>

#include "jcat-blob.h"
#include "jcat-common.h"
#include "jcat-result.h"

#define JCAT_TYPE_ENGINE (jcat_engine_get_type())
G_DECLARE_DERIVABLE_TYPE(JcatEngine, jcat_engine, JCAT, ENGINE, GObject)

struct _JcatEngineClass {
	GObjectClass parent_class;
	gboolean (*setup)(JcatEngine *self, GError **error);
	gboolean (*add_public_key)(JcatEngine *self, const gchar *filename, GError **error);
	JcatResult *(*pubkey_verify)(JcatEngine *self,
				     GBytes *blob,
				     GBytes *blob_signature,
				     JcatVerifyFlags flags,
				     GError **error);
	JcatBlob *(*pubkey_sign)(JcatEngine *self,
				 GBytes *blob,
				 GBytes *cert,
				 GBytes *privkey,
				 JcatSignFlags flags,
				 GError **error);
	JcatResult *(*self_verify)(JcatEngine *self,
				   GBytes *blob,
				   GBytes *blob_signature,
				   JcatVerifyFlags flags,
				   GError **error);
	JcatBlob *(*self_sign)(JcatEngine *self, GBytes *blob, JcatSignFlags flags, GError **error);
	gboolean (*add_public_key_raw)(JcatEngine *self, GBytes *blob, GError **error);
	gpointer padding[8];
};

JcatBlobKind
jcat_engine_get_kind(JcatEngine *self) G_GNUC_NON_NULL(1);
JcatBlobMethod
jcat_engine_get_method(JcatEngine *self) G_GNUC_NON_NULL(1);
JcatResult *
jcat_engine_pubkey_verify(JcatEngine *self,
			  GBytes *blob,
			  GBytes *blob_signature,
			  JcatVerifyFlags flags,
			  GError **error) G_GNUC_NON_NULL(1, 2, 3);
JcatBlob *
jcat_engine_pubkey_sign(JcatEngine *self,
			GBytes *blob,
			GBytes *cert,
			GBytes *privkey,
			JcatSignFlags flags,
			GError **error) G_GNUC_NON_NULL(1, 2, 3, 4);
JcatResult *
jcat_engine_self_verify(JcatEngine *self,
			GBytes *blob,
			GBytes *blob_signature,
			JcatVerifyFlags flags,
			GError **error) G_GNUC_NON_NULL(1, 2, 3);
JcatBlob *
jcat_engine_self_sign(JcatEngine *self, GBytes *blob, JcatSignFlags flags, GError **error)
    G_GNUC_NON_NULL(1, 2);
gboolean
jcat_engine_add_public_key_raw(JcatEngine *self, GBytes *blob, GError **error)
    G_GNUC_NON_NULL(1, 2);
