/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-engine-sha256.h"
#include "jcat-engine-private.h"

struct _JcatEngineSha256
{
	JcatEngine		 parent_instance;
};

G_DEFINE_TYPE (JcatEngineSha256, jcat_engine_sha256, JCAT_TYPE_ENGINE)

static GBytes *
jcat_engine_sha256_sign_data (JcatEngine *engine,
			      GBytes *data,
			      JcatSignFlags flags,
			      GError **error)
{
	g_autofree gchar *tmp = NULL;
	tmp = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, data);
	return g_bytes_new (tmp, strlen (tmp));
}

static JcatResult *
jcat_engine_sha256_verify_data (JcatEngine *engine,
				GBytes *data,
				GBytes *blob_signature,
				JcatVerifyFlags flags,
				GError **error)
{
	g_autofree gchar *tmp = NULL;
	g_autoptr(GBytes) data_tmp = NULL;

	tmp = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, data);
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
jcat_engine_sha256_finalize (GObject *object)
{
	G_OBJECT_CLASS (jcat_engine_sha256_parent_class)->finalize (object);
}

static void
jcat_engine_sha256_class_init (JcatEngineSha256Class *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS (klass);
	klass_app->sign_data = jcat_engine_sha256_sign_data;
	klass_app->verify_data = jcat_engine_sha256_verify_data;
	object_class->finalize = jcat_engine_sha256_finalize;
}

static void
jcat_engine_sha256_init (JcatEngineSha256 *self)
{
}

JcatEngine *
jcat_engine_sha256_new (void)
{
	return JCAT_ENGINE (g_object_new (JCAT_TYPE_ENGINE_SHA256,
					  "kind", JCAT_BLOB_KIND_SHA256,
					  "verify-kind", JCAT_ENGINE_VERIFY_KIND_CHECKSUM,
					  NULL));
}
