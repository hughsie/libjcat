/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-jcat-sha1-engine.h"

struct _FwupdJcatSha1Engine {
	FuJcatEngine parent_instance;
};

G_DEFINE_TYPE(FwupdJcatSha1Engine, fu_jcat_sha1_engine, FU_TYPE_JCAT_ENGINE)

static FwupdJcatBlob *
fu_jcat_sha1_engine_self_sign(FuJcatEngine *engine,
			      GBytes *data,
			      FuJcatSignFlags flags,
			      GError **error)
{
	g_autofree gchar *tmp = g_compute_checksum_for_bytes(G_CHECKSUM_SHA1, data);
	return fwupd_jcat_blob_new_utf8(FWUPD_JCAT_BLOB_KIND_SHA1, tmp);
}

static FuJcatResult *
fu_jcat_sha1_engine_self_verify(FuJcatEngine *engine,
				GBytes *data,
				GBytes *blob_signature,
				FuJcatVerifyFlags flags,
				GError **error)
{
	g_autofree gchar *tmp = NULL;
	g_autoptr(GBytes) data_tmp = NULL;

	tmp = g_compute_checksum_for_bytes(G_CHECKSUM_SHA1, data);
	data_tmp = g_bytes_new(tmp, strlen(tmp));
	if (!fu_bytes_compare(data_tmp, blob_signature, error)) {
		g_autofree gchar *sig = g_strndup(g_bytes_get_data(blob_signature, NULL),
						  g_bytes_get_size(blob_signature));
		g_prefix_error(error, "expected %s and got %s", tmp, sig);
		return NULL;
	}
	return FWUPD_JCAT_RESULT(g_object_new(FU_TYPE_JCAT_RESULT, "engine", engine, NULL));
}

static void
fu_jcat_sha1_engine_class_init(FwupdJcatSha1EngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuJcatEngineClass *engine_class = FWUPD_JCAT_ENGINE_CLASS(klass);
	engine_class->self_sign = fu_jcat_sha1_engine_self_sign;
	engine_class->self_verify = fu_jcat_sha1_engine_self_verify;
}

static void
fu_jcat_sha1_engine_init(FwupdJcatSha1Engine *self)
{
}

FuJcatEngine *
fu_jcat_sha1_engine_new(FuJcatContext *context)
{
	g_return_val_if_fail(FWUPD_JCAT_IS_CONTEXT(context), NULL);
	return FWUPD_JCAT_ENGINE(g_object_new(FU_TYPE_JCAT_SHA1_ENGINE,
					      "context",
					      context,
					      "kind",
					      FWUPD_JCAT_BLOB_KIND_SHA1,
					      "method",
					      FWUPD_JCAT_BLOB_METHOD_CHECKSUM,
					      NULL));
}
