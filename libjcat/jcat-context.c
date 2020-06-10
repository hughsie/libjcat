/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-blob.h"
#include "jcat-context-private.h"
#include "jcat-engine-private.h"
#include "jcat-result-private.h"
#include "jcat-sha1-engine.h"
#include "jcat-sha256-engine.h"

#ifdef ENABLE_GPG
#include "jcat-gpg-engine.h"
#endif
#ifdef ENABLE_PKCS7
#include "jcat-pkcs7-engine.h"
#endif

typedef struct {
	GPtrArray		*engines;
	GPtrArray		*public_keys;
	gchar			*keyring_path;
} JcatContextPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatContext, jcat_context, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_context_get_instance_private (o))

static void
jcat_context_finalize (GObject *obj)
{
	JcatContext *self = JCAT_CONTEXT (obj);
	JcatContextPrivate *priv = GET_PRIVATE (self);
	g_free (priv->keyring_path);
	g_ptr_array_unref (priv->engines);
	g_ptr_array_unref (priv->public_keys);
	G_OBJECT_CLASS (jcat_context_parent_class)->finalize (obj);
}

static void
jcat_context_class_init (JcatContextClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = jcat_context_finalize;
}

static void
jcat_context_init (JcatContext *self)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	priv->keyring_path = g_build_filename (g_get_user_data_dir (), PACKAGE_NAME, NULL);
	priv->engines = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
	priv->public_keys = g_ptr_array_new_with_free_func (g_free);

	g_ptr_array_add (priv->engines, jcat_sha1_engine_new (self));
	g_ptr_array_add (priv->engines, jcat_sha256_engine_new (self));
#ifdef ENABLE_GPG
	g_ptr_array_add (priv->engines, jcat_gpg_engine_new (self));
#endif
#ifdef ENABLE_PKCS7
	g_ptr_array_add (priv->engines, jcat_pkcs7_engine_new (self));
#endif
}

/**
 * jcat_context_add_public_key:
 * @self: #JcatContext
 * @filename: A filename
 *
 * Adds a single public key.
 *
 * Since: 0.1.0
 **/
void
jcat_context_add_public_key (JcatContext *self, const gchar *filename)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	g_return_if_fail (JCAT_IS_CONTEXT (self));
	g_return_if_fail (filename != NULL);
	g_ptr_array_add (priv->public_keys, g_strdup (filename));
}

/**
 * jcat_context_add_public_keys:
 * @self: #JcatContext
 * @path: A directory of files
 *
 * Adds a public key directory.
 *
 * Since: 0.1.0
 **/
void
jcat_context_add_public_keys (JcatContext *self, const gchar *path)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	const gchar *fn_tmp;
	g_autoptr(GDir) dir = NULL;

	g_return_if_fail (JCAT_IS_CONTEXT (self));
	g_return_if_fail (path != NULL);

	/* search all the public key files */
	dir = g_dir_open (path, 0, NULL);
	if (dir == NULL)
		return;
	while ((fn_tmp = g_dir_read_name (dir)) != NULL) {
		g_ptr_array_add (priv->public_keys,
				 g_build_filename (path, fn_tmp, NULL));
	}
}

/* private */
GPtrArray *
jcat_context_get_public_keys (JcatContext *self)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	return priv->public_keys;
}

/**
 * jcat_context_set_keyring_path:
 * @self: #JcatContext
 * @path: A directory
 *
 * Sets the local state directory for the engines to use.
 *
 * Since: 0.1.0
 **/
void
jcat_context_set_keyring_path (JcatContext *self, const gchar *path)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	g_return_if_fail (JCAT_IS_CONTEXT (self));
	g_return_if_fail (path != NULL);
	g_free (priv->keyring_path);
	priv->keyring_path = g_strdup (path);
}

/**
 * jcat_context_get_keyring_path:
 * @self: #JcatContext
 *
 * Gets the local state directory the engines are using.
 *
 * Returns: (nullable): path
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_context_get_keyring_path (JcatContext *self)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_CONTEXT (self), NULL);
	return priv->keyring_path;
}

/**
 * jcat_context_get_engine:
 * @self: #JcatContext
 * @kind: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_GPG
 * @error: #GError, or %NULL
 *
 * Gets the engine for a specific engine kind, setting up the context
 * automartically if requried.
 *
 * Returns: (transfer full): #JcatEngine, or %NULL for unavailable
 *
 * Since: 0.1.0
 **/
JcatEngine *
jcat_context_get_engine (JcatContext *self, JcatBlobKind kind, GError **error)
{
	JcatContextPrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (JCAT_IS_CONTEXT (self), NULL);

	for (guint i = 0; i < priv->engines->len; i++) {
		JcatEngine *engine = g_ptr_array_index (priv->engines, i);
		if (jcat_engine_get_kind (engine) == kind)
			return g_object_ref (engine);
	}
	g_set_error (error,
		     G_IO_ERROR,
		     G_IO_ERROR_NOT_FOUND,
		     "Jcat engine kind '%s' not supported",
		     jcat_blob_kind_to_string (kind));
	return NULL;
}

/**
 * jcat_context_verify_blob:
 * @self: #JcatContext
 * @data: #GBytes
 * @blob: #JcatBlob
 * @flags: #JcatVerifyFlags, e.g. %JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS
 * @error: #GError, or %NULL
 *
 * Verifies a #JcatBlob using the public keys added to the context.
 *
 * Returns: (transfer full): #JcatResult, or %NULL for failed
 *
 * Since: 0.1.0
 **/
JcatResult *
jcat_context_verify_blob (JcatContext *self,
			  GBytes *data,
			  JcatBlob *blob,
			  JcatVerifyFlags flags,
			  GError **error)
{
	GBytes *blob_signature;
	g_autoptr(JcatEngine) engine = NULL;

	g_return_val_if_fail (JCAT_IS_CONTEXT (self), NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (JCAT_IS_BLOB (blob), NULL);

	/* get correct engine */
	engine = jcat_context_get_engine (self, jcat_blob_get_kind (blob), error);
	if (engine == NULL)
		return NULL;
	blob_signature = jcat_blob_get_data (blob);
	return jcat_engine_pubkey_verify (engine, data, blob_signature, flags, error);
}

/**
 * jcat_context_verify_item:
 * @self: #JcatContext
 * @data: #GBytes
 * @item: #JcatItem
 * @flags: #JcatVerifyFlags, e.g. %JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE
 * @error: #GError, or %NULL
 *
 * Verifies a #JcatItem using the public keys added to the context. All
 * `verify=CHECKSUM` engines (e.g. SHA256) must verify correctly,
 * but only one non-checksum signature has to verify.
 *
 * Returns: (transfer container) (element-type JcatResult): array of #JcatResult, or %NULL for failed
 *
 * Since: 0.1.0
 **/
GPtrArray *
jcat_context_verify_item (JcatContext *self,
			  GBytes *data,
			  JcatItem *item,
			  JcatVerifyFlags flags,
			  GError **error)
{
	guint nr_signature = 0;
	g_autoptr(GPtrArray) blobs = NULL;
	g_autoptr(GPtrArray) results = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);

	g_return_val_if_fail (JCAT_IS_CONTEXT (self), NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (JCAT_IS_ITEM (item), NULL);

	/* no blobs */
	blobs = jcat_item_get_blobs (item);
	if (blobs->len == 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "no blobs in item");
		return NULL;
	}

	/* all checksum engines must verify */
	for (guint i = 0; i < blobs->len; i++) {
		JcatBlob *blob = g_ptr_array_index (blobs, i);
		g_autoptr(JcatEngine) engine = NULL;
		g_autoptr(JcatResult) result = NULL;

		/* get engine */
		engine = jcat_context_get_engine (self, jcat_blob_get_kind (blob), error);
		if (engine == NULL)
			return NULL;
		if (jcat_engine_get_method (engine) != JCAT_BLOB_METHOD_CHECKSUM)
			continue;
		result = jcat_engine_self_verify (engine, data, jcat_blob_get_data (blob), flags, error);
		if (result == NULL) {
			g_prefix_error (error, "checksum failure: ");
			return NULL;
		}
		g_ptr_array_add (results, g_steal_pointer (&result));
	}
	if (flags & JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM && results->len == 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "checksums were required, but none supplied");
		return NULL;
	}

	/* we only have to have one non-checksum method to verify */
	for (guint i = 0; i < blobs->len; i++) {
		JcatBlob *blob = g_ptr_array_index (blobs, i);
		g_autofree gchar *result_str = NULL;
		g_autoptr(GError) error_local = NULL;
		g_autoptr(JcatEngine) engine = NULL;
		g_autoptr(JcatResult) result = NULL;

		engine = jcat_context_get_engine (self, jcat_blob_get_kind (blob), error);
		if (engine == NULL)
			return NULL;
		if (jcat_engine_get_method (engine) != JCAT_BLOB_METHOD_SIGNATURE)
			continue;
		result = jcat_engine_pubkey_verify (engine, data, jcat_blob_get_data (blob), flags, &error_local);
		if (result == NULL) {
			g_debug ("signature failure: %s", error_local->message);
			continue;
		}
		result_str = jcat_result_to_string (result);
		g_debug ("verified: %s", result_str);
		g_ptr_array_add (results, g_steal_pointer (&result));
		nr_signature++;
	}
	if (flags & JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE && nr_signature == 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "signatures were required, but none supplied");
		return NULL;
	}

	/* success */
	return g_steal_pointer (&results);
}

/**
 * jcat_context_new:
 *
 * Creates a new context.
 *
 * Returns: a #JcatContext
 *
 * Since: 0.1.0
 **/
JcatContext *
jcat_context_new (void)
{
	return g_object_new (JCAT_TYPE_CONTEXT, NULL);
}
