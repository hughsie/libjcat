/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-blob-private.h"
#include "jcat-item-private.h"

typedef struct {
	gchar			*id;
	GPtrArray		*blobs;
} JcatItemPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatItem, jcat_item, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_item_get_instance_private (o))

static void
jcat_item_finalize (GObject *obj)
{
	JcatItem *self = JCAT_ITEM (obj);
	JcatItemPrivate *priv = GET_PRIVATE (self);
	g_free (priv->id);
	g_ptr_array_unref (priv->blobs);
	G_OBJECT_CLASS (jcat_item_parent_class)->finalize (obj);
}

static void
jcat_item_class_init (JcatItemClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = jcat_item_finalize;
}

static void
jcat_item_init (JcatItem *self)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);
	priv->blobs = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
}

/* private */
void
jcat_item_add_string (JcatItem *self, guint idt, GString *str)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);
	jcat_string_append_kv (str, idt, G_OBJECT_TYPE_NAME (self), NULL);
	jcat_string_append_kv (str, idt + 1, "ID", priv->id);
	for (guint i = 0; i < priv->blobs->len; i++) {
		JcatBlob *blob = g_ptr_array_index (priv->blobs, i);
		jcat_blob_add_string (blob, idt + 1, str);
	}
}

/**
 * jcat_item_to_string:
 * @self: #JcatItem
 *
 * Converts the #JcatItem to a string.
 *
 * Returns: string
 *
 * Since: 0.1.0
 **/
gchar *
jcat_item_to_string (JcatItem *self)
{
	GString *str = g_string_new (NULL);
	jcat_item_add_string (self, 0, str);
	return g_string_free (str, FALSE);
}

/* private */
JcatItem *
jcat_item_import (JsonObject *obj, JcatImportFlags flags, GError **error)
{
	const gchar *required[] = { "Id", "Blobs", NULL };
	g_autoptr(GList) elements = NULL;
	g_autoptr(JcatItem) self = g_object_new (JCAT_TYPE_ITEM, NULL);
	JcatItemPrivate *priv = GET_PRIVATE (self);

	/* sanity check */
	for (guint i = 0; required[i] != NULL; i++) {
		if (!json_object_has_member (obj, required[i])) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "failed to find %s",
				     required[i]);
			return NULL;
		}
	}

	/* get ID */
	priv->id = g_strdup (json_object_get_string_member (obj, "Id"));

	/* get blobs */
	elements = json_array_get_elements (json_object_get_array_member (obj, "Blobs"));
	for (GList *l = elements; l != NULL; l = l->next) {
		g_autoptr(JcatBlob) blob = NULL;
		JsonNode *node = l->data;
		if (!JSON_NODE_HOLDS_OBJECT (node)) {
			g_set_error_literal (error,
					     G_IO_ERROR,
					     G_IO_ERROR_INVALID_DATA,
					     "failed to read object");
			return NULL;
		}
		blob = jcat_blob_import (json_node_get_object (node), flags, error);
		if (blob == NULL)
			return NULL;
		jcat_item_add_blob (self, blob);
	}

	/* success */
	return g_steal_pointer (&self);
}

void
jcat_item_export (JcatItem *self, JcatExportFlags flags, JsonBuilder *builder)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);

	/* add metadata */
	json_builder_set_member_name (builder, "Id");
	json_builder_add_string_value (builder, priv->id);

	/* add items */
	if (priv->blobs->len > 0) {
		json_builder_set_member_name (builder, "Blobs");
		json_builder_begin_array (builder);
		for (guint i = 0; i < priv->blobs->len; i++) {
			JcatBlob *blob = g_ptr_array_index (priv->blobs, i);
			json_builder_begin_object (builder);
			jcat_blob_export (blob, flags, builder);
			json_builder_end_object (builder);
		}
		json_builder_end_array (builder);
	}
}

/**
 * jcat_item_get_blobs:
 * @self: #JcatItem
 *
 * Gets all the blobs for this item.
 *
 * Returns: (transfer container) (element-type JcatBlob): blobs
 *
 * Since: 0.1.0
 **/
GPtrArray *
jcat_item_get_blobs (JcatItem *self)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_ITEM (self), NULL);
	return g_ptr_array_ref (priv->blobs);
}

/**
 * jcat_item_get_blobs_by_kind:
 * @self: #JcatItem
 * @kind: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 *
 * Gets the item blobs by a specific kind.
 *
 * Returns: (transfer container) (element-type JcatBlob): blobs
 *
 * Since: 0.1.0
 **/
GPtrArray *
jcat_item_get_blobs_by_kind (JcatItem *self, JcatBlobKind kind)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);
	GPtrArray *blobs = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);

	g_return_val_if_fail (JCAT_IS_ITEM (self), NULL);
	g_return_val_if_fail (kind != JCAT_BLOB_KIND_UNKNOWN, NULL);

	for (guint i = 0; i < priv->blobs->len; i++) {
		JcatBlob *blob = g_ptr_array_index (priv->blobs, i);
		if (jcat_blob_get_kind (blob) == kind)
			g_ptr_array_add (blobs, g_object_ref (blob));
	}
	return blobs;
}

/**
 * jcat_item_add_blob:
 * @self: #JcatItem
 * @blob: #JcatBlob
 *
 * Adds a new blob to the item.
 *
 * Since: 0.1.0
 **/
void
jcat_item_add_blob (JcatItem *self, JcatBlob *blob)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);

	g_return_if_fail (JCAT_IS_ITEM (self));
	g_return_if_fail (JCAT_IS_BLOB (blob));

	/* remove existing blob with this AppStream ID and kind */
	for (guint i = 0; i < priv->blobs->len; i++) {
		JcatBlob *blob_tmp = g_ptr_array_index (priv->blobs, i);
		if (jcat_blob_get_kind (blob_tmp) == jcat_blob_get_kind (blob) &&
		    g_strcmp0 (jcat_blob_get_appstream_id (blob_tmp),
			       jcat_blob_get_appstream_id (blob)) == 0) {
			g_ptr_array_remove (priv->blobs, blob_tmp);
			break;
		}
	}

	/* add */
	g_ptr_array_add (priv->blobs, g_object_ref (blob));
}

/**
 * jcat_item_get_id:
 * @self: #JcatItem
 *
 * Returns the item ID.
 *
 * Returns: (transfer none): string
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_item_get_id (JcatItem *self)
{
	JcatItemPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_ITEM (self), NULL);
	return priv->id;
}

/**
 * jcat_item_new:
 * @id: An item ID, typically a file basename
 *
 * Creates a new item.
 *
 * Returns: a #JcatItem
 *
 * Since: 0.1.0
 **/
JcatItem *
jcat_item_new (const gchar *id)
{
	JcatItem *self = g_object_new (JCAT_TYPE_ITEM, NULL);
	JcatItemPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (id != NULL, NULL);
	priv->id = g_strdup (id);
	return self;
}
