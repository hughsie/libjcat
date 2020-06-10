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
	JcatBlobMethod		 method;
	gboolean		 done_setup;
} JcatEnginePrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatEngine, jcat_engine, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_engine_get_instance_private (o))

enum {
	PROP_0,
	PROP_CONTEXT,
	PROP_KIND,
	PROP_METHOD,
	PROP_LAST
};

static const gchar *
jcat_engine_method_to_string (JcatBlobMethod method)
{
	if (method == JCAT_BLOB_METHOD_CHECKSUM)
		return "checksum";
	if (method == JCAT_BLOB_METHOD_SIGNATURE)
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
			       jcat_engine_method_to_string (priv->method));
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
	if (klass->add_public_key != NULL) {
		GPtrArray *fns = jcat_context_get_public_keys (priv->context);
		for (guint i = 0; i < fns->len; i++) {
			const gchar *fn = g_ptr_array_index (fns, i);
			if (!klass->add_public_key (self, fn, error))
				return FALSE;
		}
	}

	/* success */
	priv->done_setup = TRUE;
	return TRUE;
}

/**
 * jcat_engine_pubkey_verify:
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
jcat_engine_pubkey_verify (JcatEngine *self,
			   GBytes *blob,
			   GBytes *blob_signature,
			   JcatVerifyFlags flags,
			   GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	g_return_val_if_fail (blob_signature != NULL, NULL);
	if (klass->pubkey_verify == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "verifying data is not supported");
		return NULL;
	}
	if (!jcat_engine_setup (self, error))
		return NULL;
	return klass->pubkey_verify (self, blob, blob_signature, flags, error);
}

/**
 * jcat_engine_pubkey_sign:
 * @self: #JcatEngine
 * @blob: #GBytes
 * @cert: #GBytes
 * @privkey: #GBytes
 * @flags: #JcatSignFlags, e.g. %JCAT_SIGN_FLAG_ADD_TIMESTAMP
 * @error: #GError, or %NULL
 *
 * Signs a chunk of data.
 *
 * Returns: (transfer full): #JcatBlob, or %NULL for failed
 *
 * Since: 0.1.0
 **/
JcatBlob *
jcat_engine_pubkey_sign (JcatEngine *self,
			 GBytes *blob,
			 GBytes *cert,
			 GBytes *privkey,
			 JcatSignFlags flags,
			 GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	g_return_val_if_fail (cert != NULL, NULL);
	g_return_val_if_fail (privkey != NULL, NULL);
	if (klass->pubkey_sign == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "signing data is not supported");
		return NULL;
	}
	if (!jcat_engine_setup (self, error))
		return NULL;
	return klass->pubkey_sign (self, blob, cert, privkey, flags, error);
}

/**
 * jcat_engine_self_verify:
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
jcat_engine_self_verify (JcatEngine *self,
			 GBytes *blob,
			 GBytes *blob_signature,
			 JcatVerifyFlags flags,
			 GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	g_return_val_if_fail (blob_signature != NULL, NULL);
	if (klass->self_verify == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "verifying data is not supported");
		return NULL;
	}
	if (!jcat_engine_setup (self, error))
		return NULL;
	return klass->self_verify (self, blob, blob_signature, flags, error);
}

/**
 * jcat_engine_self_sign:
 * @self: #JcatEngine
 * @blob: #GBytes
 * @flags: #JcatSignFlags, e.g. %JCAT_SIGN_FLAG_ADD_TIMESTAMP
 * @error: #GError, or %NULL
 *
 * Signs a chunk of data.
 *
 * Returns: (transfer full): #JcatBlob, or %NULL for failed
 *
 * Since: 0.1.0
 **/
JcatBlob *
jcat_engine_self_sign (JcatEngine *self,
		       GBytes *blob,
		       JcatSignFlags flags,
		       GError **error)
{
	JcatEngineClass *klass = JCAT_ENGINE_GET_CLASS (self);
	g_return_val_if_fail (JCAT_IS_ENGINE (self), NULL);
	g_return_val_if_fail (blob != NULL, NULL);
	if (klass->self_sign == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "signing data is not supported");
		return NULL;
	}
	if (!jcat_engine_setup (self, error))
		return NULL;
	return klass->self_sign (self, blob, flags, error);
}

/**
 * jcat_engine_get_kind:
 * @self: #JcatEngine
 *
 * Gets the blob kind.
 *
 * Returns: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 *
 * Since: 0.1.3
 **/
JcatBlobKind
jcat_engine_get_kind (JcatEngine *self)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	return priv->kind;
}

/**
 * jcat_engine_get_method:
 * @self: #JcatEngine
 *
 * Gets the verification method.
 *
 * Returns: #JcatBlobMethod, e.g. %JCAT_BLOB_METHOD_SIGNATURE
 *
 * Since: 0.1.3
 **/
JcatBlobMethod
jcat_engine_get_method (JcatEngine *self)
{
	JcatEnginePrivate *priv = GET_PRIVATE (self);
	return priv->method;
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
	case PROP_METHOD:
		g_value_set_uint (value, priv->method);
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
	case PROP_METHOD:
		priv->method = g_value_get_uint (value);
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

	pspec = g_param_spec_uint ("method", NULL, NULL,
				   JCAT_BLOB_METHOD_UNKNOWN,
				   JCAT_BLOB_METHOD_LAST,
				   JCAT_BLOB_METHOD_UNKNOWN,
				   G_PARAM_READWRITE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_METHOD, pspec);
	object_class->finalize = jcat_engine_finalize;
}

static void
jcat_engine_init (JcatEngine *self)
{
}
