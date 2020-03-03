/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-context-private.h"
#include "jcat-engine-private.h"

typedef struct {
	JcatContext		*context;		/* weak */
	JcatBlobKind		 kind;
	JcatEngineVerifyKind	 verify_kind;
	gboolean		 done_setup;
} JcatEnginePrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatEngine, jcat_engine, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_engine_get_instance_private (o))

enum {
	PROP_0,
	PROP_CONTEXT,
	PROP_KIND,
	PROP_VERIFY_KIND,
	PROP_LAST
};

static const gchar *
jcat_engine_verify_kind_to_string (JcatEngineVerifyKind verify_kind)
{
	if (verify_kind == JCAT_ENGINE_VERIFY_KIND_CHECKSUM)
		return "checksum";
	if (verify_kind == JCAT_ENGINE_VERIFY_KIND_SIGNATURE)
		return "signature";
	return NULL;
}

/* private */
void
jcat_engine_add_string (JcatEngine *self, guint idt, GString *str)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	jcat_string_append_kv (str, idt, G_OBJECT_TYPE_NAME (self), NULL);
	jcat_string_append_kv (str, idt + 1, "Kind",
			       jcat_blob_kind_to_string (priv->kind));
	jcat_string_append_kv (str, idt + 1, "VerifyKind",
			       jcat_engine_verify_kind_to_string (priv->verify_kind));
}

/* private */
gchar *
jcat_engine_to_string (JcatEngine *self)
{
	GString *str = g_string_new (NULL);
	jcat_engine_add_string (self, 0, str);
	return g_string_free (str, FALSE);
}

static gboolean
jcat_engine_setup (JcatEngine *self, GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	JcatEnginePrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (JCAT_IS_ENGINE (self), FALSE);

	/* already done */
	if (priv->done_setup)
		return TRUE;

	/* optional */
	if (klass->setup != NULL) {
		if (!klass->setup (self, error))
			return FALSE;
	}
	if (klass->add_public_keys != NULL) {
		GPtrArray *paths = jcat_context_get_public_key_paths (priv->context);
		for (guint i = 0; i < paths->len; i++) {
			const gchar *path = g_ptr_array_index (paths, i);
			if (!klass->add_public_keys (self, path, error))
				return FALSE;
		}
	}

	/* success */
	priv->done_setup = TRUE;
	return TRUE;
}

/**
 * jcat_engine_verify:
 * @self: #JcatEngine
 * @blob: #GBytes
 * @blob_signature: #GBytes
 * @flags: #JcatVerifyFlags, e.g. %JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS
 * @error: #GError, or %NULL
 *
 * Verifies a chunk of data.
 *
 * Returns: (transfer full): #JcatResult, or %NULL for failed
 *
 * Since: 0.1.0
 **/
JcatResult *
jcat_engine_verify (JcatEngine *self,
		    GBytes *blob,
		    GBytes *blob_signature,
		    JcatVerifyFlags flags,
		    GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	g_return_val_if_fail (blob_signature != NULL, NULL);
	if (!jcat_engine_setup (self, error))
		return NULL;
	return klass->verify_data (self, blob, blob_signature, flags, error);
}

/**
 * jcat_engine_sign:
 * @self: #JcatEngine
 * @blob: #GBytes
 * @flags: #JcatSignFlags, e.g. %JCAT_SIGN_FLAG_ADD_TIMESTAMP
 * @error: #GError, or %NULL
 *
 * Signs a chunk of data.
 *
 * Returns: (transfer full): #GBytes, or %NULL for failed
 *
 * Since: 0.1.0
 **/
GBytes *
jcat_engine_sign (JcatEngine *self,
		  GBytes *blob,
		  JcatSignFlags flags,
		  GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	if (klass->sign_data == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "signing data is not supported");
		return NULL;
	}
	if (!jcat_engine_setup (self, error))
		return FALSE;
	return klass->sign_data (self, blob, flags, error);
}

JcatBlobKind
jcat_engine_get_kind (JcatEngine *self)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	return priv->kind;
}

JcatEngineVerifyKind
jcat_engine_get_verify_kind (JcatEngine *self)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	return priv->verify_kind;
}

const gchar *
jcat_engine_get_keyring_path (JcatEngine *self)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	if (priv->context == NULL)
		return NULL;
	return jcat_context_get_keyring_path (priv->context);
}

static void
jcat_engine_finalize (GObject *object)
{
	G_OBJECT_CLASS (jcat_engine_parent_class)->finalize (object);
}

static void
jcat_engine_get_property (GObject *object, guint prop_id,
				GValue *value, GParamSpec *pspec)
{
	JcatEngine *self = JCAT_ENGINE (object);
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	switch (prop_id) {
	case PROP_CONTEXT:
		g_value_set_object (value, priv->context);
		break;
	case PROP_KIND:
		g_value_set_uint (value, priv->kind);
		break;
	case PROP_VERIFY_KIND:
		g_value_set_uint (value, priv->verify_kind);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
jcat_engine_set_property (GObject *object, guint prop_id,
				const GValue *value, GParamSpec *pspec)
{
	JcatEngine *self = JCAT_ENGINE (object);
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	switch (prop_id) {
	case PROP_CONTEXT:
		/* weak */
		priv->context = g_value_get_object (value);
		break;
	case PROP_KIND:
		priv->kind = g_value_get_uint (value);
		break;
	case PROP_VERIFY_KIND:
		priv->verify_kind = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
jcat_engine_class_init (JcatEngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GParamSpec *pspec;

	object_class->get_property = jcat_engine_get_property;
	object_class->set_property = jcat_engine_set_property;

	pspec = g_param_spec_object ("context", NULL, NULL,
				     JCAT_TYPE_CONTEXT,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_CONTEXT, pspec);

	pspec = g_param_spec_uint ("kind", NULL, NULL,
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_KIND, pspec);

	pspec = g_param_spec_uint ("verify-kind", NULL, NULL,
				   JCAT_ENGINE_VERIFY_KIND_UNKNOWN,
				   JCAT_ENGINE_VERIFY_KIND_LAST,
				   JCAT_ENGINE_VERIFY_KIND_UNKNOWN,
				   G_PARAM_READWRITE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_VERIFY_KIND, pspec);
	object_class->finalize = jcat_engine_finalize;
}

static void
jcat_engine_init (JcatEngine *self)
{
}
