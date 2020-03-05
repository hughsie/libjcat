/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-sha1-engine.h"
#include "jcat-engine-private.h"

struct _JcatSha1Engine
{
	JcatEngine		 parent_instance;
};

G_DEFINE_TYPE (JcatSha1Engine, jcat_sha1_engine, JCAT_TYPE_ENGINE)

static JcatBlob *
jcat_sha1_engine_self_sign (JcatEngine *engine,
			      GBytes *data,
			      JcatSignFlags flags,
			      GError **error)
{
	g_autofree gchar *tmp = NULL;
	tmp = g_compute_checksum_for_bytes (G_CHECKSUM_SHA1, data);
	return jcat_blob_new_utf8 (JCAT_BLOB_KIND_SHA1, tmp);
}

static JcatResult *
jcat_sha1_engine_self_verify (JcatEngine *engine,
				GBytes *data,
				GBytes *blob_signature,
				JcatVerifyFlags flags,
				GError **error)
{
	g_autofree gchar *tmp = NULL;
	g_autoptr(GBytes) data_tmp = NULL;

	tmp = g_compute_checksum_for_bytes (G_CHECKSUM_SHA1, data);
	data_tmp = g_bytes_new (tmp, strlen (tmp));
	if (g_bytes_compare (data_tmp, blob_signature) != 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "failed to verify data, expected %s",
			     tmp);
		return NULL;
	}
	return JCAT_RESULT (g_object_new (JCAT_TYPE_RESULT,
					  "engine", engine,
					  NULL));
}

static void
jcat_sha1_engine_finalize (GObject *object)
{
	G_OBJECT_CLASS (jcat_sha1_engine_parent_class)->finalize (object);
}

static void
jcat_sha1_engine_class_init (JcatSha1EngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS (klass);
	klass_app->self_sign = jcat_sha1_engine_self_sign;
	klass_app->self_verify = jcat_sha1_engine_self_verify;
	object_class->finalize = jcat_sha1_engine_finalize;
}

static void
jcat_sha1_engine_init (JcatSha1Engine *self)
{
}

JcatEngine *
jcat_sha1_engine_new (JcatContext *context)
{
	g_return_val_if_fail (JCAT_IS_CONTEXT (context), NULL);
	return JCAT_ENGINE (g_object_new (JCAT_TYPE_SHA1_ENGINE,
					  "context", context,
					  "kind", JCAT_BLOB_KIND_SHA1,
					  "verify-kind", JCAT_ENGINE_VERIFY_KIND_CHECKSUM,
					  NULL));
}
