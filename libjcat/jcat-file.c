/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <json-glib/json-glib.h>

#include "jcat-common-private.h"
#include "jcat-file-private.h"
#include "jcat-item-private.h"

typedef struct {
	GPtrArray		*items;
	guint32			 version_major;
	guint32			 version_minor;
} JcatFilePrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatFile, jcat_file, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_file_get_instance_private (o))

static void
jcat_file_finalize (GObject *obj)
{
	JcatFile *self = JCAT_FILE (obj);
	JcatFilePrivate *priv = GET_PRIVATE (self);

	g_ptr_array_unref (priv->items);
	G_OBJECT_CLASS (jcat_file_parent_class)->finalize (obj);
}

static void
jcat_file_class_init (JcatFileClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = jcat_file_finalize;
}

static void
jcat_file_init (JcatFile *self)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	priv->items = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
}

/* private */
void
jcat_file_add_string (JcatFile *self, guint idt, GString *str)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	jcat_string_append_kv (str, idt, G_OBJECT_TYPE_NAME (self), NULL);
	if (priv->version_major > 0 || priv->version_minor > 0) {
		g_autofree gchar *version = NULL;
		version = g_strdup_printf ("%u.%u",
					   priv->version_major,
					   priv->version_minor);
		jcat_string_append_kv (str, idt + 1, "Version", version);
	}
	for (guint i = 0; i < priv->items->len; i++) {
		JcatItem *item = g_ptr_array_index (priv->items, i);
		jcat_item_add_string (item, idt + 1, str);
	}
}

/**
 * jcat_file_to_string:
 * @self: #JcatFile
 *
 * Converts the #JcatFile to a string.
 *
 * Returns: string
 *
 * Since: 0.1.0
 **/
gchar *
jcat_file_to_string (JcatFile *self)
{
	GString *str = g_string_new (NULL);
	jcat_file_add_string (self, 0, str);
	return g_string_free (str, FALSE);
}

static gboolean
jcat_file_import_parser (JcatFile *self,
			 JsonParser *parser,
			 JcatImportFlags flags,
			 GError **error)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	JsonObject *obj;
	const gchar *required[] = { "JcatVersionMajor", "JcatVersionMinor", "Items", NULL };
	g_autoptr(GList) elements = NULL;

	/* sanity check */
	obj = json_node_get_object (json_parser_get_root (parser));
	for (guint i = 0; required[i] != NULL; i++) {
		if (!json_object_has_member (obj, required[i])) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_DATA,
				     "failed to find %s",
				     required[i]);
			return FALSE;
		}
	}

	/* get version */
	priv->version_major = json_object_get_int_member (obj, "JcatVersionMajor");
	priv->version_minor = json_object_get_int_member (obj, "JcatVersionMinor");

	/* get items */
	elements = json_array_get_elements (json_object_get_array_member (obj, "Items"));
	for (GList *l = elements; l != NULL; l = l->next) {
		g_autoptr(JcatItem) item = NULL;
		JsonNode *node = l->data;
		if (!JSON_NODE_HOLDS_OBJECT (node)) {
			g_set_error_literal (error,
					     G_IO_ERROR,
					     G_IO_ERROR_INVALID_DATA,
					     "failed to read object");
			return FALSE;
		}
		item = jcat_item_import (json_node_get_object (node), flags, error);
		if (item == NULL)
			return FALSE;
		jcat_file_add_item (self, item);
	}
	return TRUE;
}

static void
jcat_file_export_builder (JcatFile *self,
			  JsonBuilder *builder,
			  JcatExportFlags flags)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	json_builder_begin_object (builder);

	/* add metadata */
	json_builder_set_member_name (builder, "JcatVersionMajor");
	json_builder_add_int_value (builder, priv->version_major);
	json_builder_set_member_name (builder, "JcatVersionMinor");
	json_builder_add_int_value (builder, priv->version_minor);

	/* add items */
	if (priv->items->len > 0) {
		json_builder_set_member_name (builder, "Items");
		json_builder_begin_array (builder);
		for (guint i = 0; i < priv->items->len; i++) {
			JcatItem *item = g_ptr_array_index (priv->items, i);
			json_builder_begin_object (builder);
			jcat_item_export (item, flags, builder);
			json_builder_end_object (builder);
		}
		json_builder_end_array (builder);
	}

	json_builder_end_object (builder);
}

/**
 * jcat_file_import_json:
 * @self: #JcatFile
 * @json: JSON data
 * @flags: #JcatImportFlags, typically %JCAT_IMPORT_FLAG_NONE
 * @error: #GError, or %NULL
 *
 * Imports a Jcat file from raw JSON.
 *
 * Returns: %TRUE for success
 *
 * Since: 0.1.0
 **/
gboolean
jcat_file_import_json (JcatFile *self,
		       const gchar *json,
		       JcatImportFlags flags,
		       GError **error)
{
	g_autoptr(JsonParser) parser = json_parser_new ();
	g_return_val_if_fail (JCAT_IS_FILE (self), FALSE);
	g_return_val_if_fail (json != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	if (!json_parser_load_from_data (parser, json, -1, error))
		return FALSE;
	return jcat_file_import_parser (self, parser, flags, error);
}

/**
 * jcat_file_import_stream:
 * @self: #JcatFile
 * @istream: #GInputStream
 * @flags: #JcatImportFlags, typically %JCAT_IMPORT_FLAG_NONE
 * @cancellable: #GCancellable, or %NULL
 * @error: #GError, or %NULL
 *
 * Imports a compressed Jcat file from a file.
 *
 * Returns: %TRUE for success
 *
 * Since: 0.1.0
 **/
gboolean
jcat_file_import_stream (JcatFile *self,
			 GInputStream *istream,
			 JcatImportFlags flags,
			 GCancellable *cancellable,
			 GError **error)
{
	g_autoptr(GConverter) conv = NULL;
	g_autoptr(GInputStream) istream_uncompressed = NULL;
	g_autoptr(JsonParser) parser = json_parser_new ();

	g_return_val_if_fail (JCAT_IS_FILE (self), FALSE);
	g_return_val_if_fail (G_IS_INPUT_STREAM (istream), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	conv = G_CONVERTER (g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP));
	istream_uncompressed = g_converter_input_stream_new (istream, conv);
	if (!json_parser_load_from_stream (parser,
					   istream_uncompressed,
					   cancellable,
					   error))
		return FALSE;
	return jcat_file_import_parser (self, parser, flags, error);
}

/**
 * jcat_file_import_file:
 * @self: #JcatFile
 * @gfile: #gfile
 * @flags: #JcatImportFlags, typically %JCAT_IMPORT_FLAG_NONE
 * @cancellable: #GCancellable, or %NULL
 * @error: #GError, or %NULL
 *
 * Imports a compressed Jcat file from an input stream.
 *
 * Returns: %TRUE for success
 *
 * Since: 0.1.0
 **/
gboolean
jcat_file_import_file (JcatFile *self,
		       GFile *gfile,
		       JcatImportFlags flags,
		       GCancellable *cancellable,
		       GError **error)
{
	g_autoptr(GInputStream) istream = NULL;

	g_return_val_if_fail (JCAT_IS_FILE (self), FALSE);
	g_return_val_if_fail (G_IS_FILE (gfile), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	istream = G_INPUT_STREAM (g_file_read (gfile, cancellable, error));
	if (istream == NULL)
		return FALSE;
	return jcat_file_import_stream (self, istream, flags, cancellable, error);
}

/**
 * jcat_file_export_json:
 * @self: #JcatFile
 * @flags: a #JcatExportFlags, typically %JCAT_EXPORT_FLAG_NONE
 * @error: #GError, or %NULL
 *
 * Exports a Jcat file to raw JSON.
 *
 * Returns: (transfer full): JSON output, or %NULL for error
 *
 * Since: 0.1.0
 **/
gchar *
jcat_file_export_json (JcatFile *self, JcatExportFlags flags, GError **error)
{
	g_autoptr(JsonBuilder) builder = json_builder_new ();
	g_autoptr(JsonGenerator) generator = json_generator_new ();
	g_autoptr(JsonNode) root = NULL;

	g_return_val_if_fail (JCAT_IS_FILE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* export all */
	jcat_file_export_builder (self, builder, flags);
	root = json_builder_get_root (builder);
	json_generator_set_root (generator, root);
	json_generator_set_pretty (generator, TRUE);
	return json_generator_to_data (generator, NULL);
}

/**
 * jcat_file_export_stream:
 * @self: #JcatFile
 * @ostream: #GOutputStream
 * @flags: a #JcatExportFlags, typically %JCAT_EXPORT_FLAG_NONE
 * @cancellable: #GCancellable, or %NULL
 * @error: #GError, or %NULL
 *
 * Exports a Jcat file to a compressed stream.
 *
 * Returns: %TRUE for success
 *
 * Since: 0.1.0
 **/
gboolean
jcat_file_export_stream (JcatFile *self,
			 GOutputStream *ostream,
			 JcatExportFlags flags,
			 GCancellable *cancellable,
			 GError **error)
{
	g_autoptr(GConverter) conv = NULL;
	g_autoptr(GOutputStream) ostream_compressed = NULL;
	g_autoptr(JsonBuilder) builder = json_builder_new ();
	g_autoptr(JsonGenerator) generator = json_generator_new ();
	g_autoptr(JsonNode) root = NULL;

	g_return_val_if_fail (JCAT_IS_FILE (self), FALSE);
	g_return_val_if_fail (G_IS_OUTPUT_STREAM (ostream), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* export all */
	jcat_file_export_builder (self, builder, flags);
	root = json_builder_get_root (builder);
	json_generator_set_root (generator, root);
	json_generator_set_pretty (generator, FALSE);

	/* compress file */
	conv = G_CONVERTER (g_zlib_compressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP, -1));
	ostream_compressed = g_converter_output_stream_new (ostream, conv);
	return json_generator_to_stream (generator, ostream_compressed, cancellable, error);
}

/**
 * jcat_file_export_file:
 * @self: #JcatFile
 * @gfile: #gfile
 * @flags: a #JcatExportFlags, typically %JCAT_EXPORT_FLAG_NONE
 * @cancellable: #GCancellable, or %NULL
 * @error: #GError, or %NULL
 *
 * Exports a Jcat file to a compressed file.
 *
 * Returns: %TRUE for success
 *
 * Since: 0.1.0
 **/
gboolean
jcat_file_export_file (JcatFile *self,
		       GFile *gfile,
		       JcatExportFlags flags,
		       GCancellable *cancellable,
		       GError **error)
{
	g_autoptr(GOutputStream) ostream = NULL;

	g_return_val_if_fail (JCAT_IS_FILE (self), FALSE);
	g_return_val_if_fail (G_IS_FILE (gfile), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	ostream = G_OUTPUT_STREAM (g_file_replace (gfile, NULL, FALSE, G_FILE_CREATE_NONE, cancellable, error));
	if (ostream == NULL)
		return FALSE;
	return jcat_file_export_stream (self, ostream, flags, cancellable, error);
}

/**
 * jcat_file_get_items:
 * @self: #JcatFile
 *
 * Returns all the items in the file.
 *
 * Returns: (transfer container) (element-type JcatItem): all the items in the file
 *
 * Since: 0.1.0
 **/
GPtrArray *
jcat_file_get_items (JcatFile *self)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_FILE (self), NULL);
	return g_ptr_array_ref (priv->items);
}

/**
 * jcat_file_get_item_by_id:
 * @self: #JcatFile
 * @id: An ID, typically a filename basename
 * @error: #GError, or %NULL
 *
 * Finds the item with the specified ID, falling back to the ID alias if set.
 *
 * Returns: (transfer full): a #JcatItem, or %NULL if the filename was not found
 *
 * Since: 0.1.0
 **/
JcatItem *
jcat_file_get_item_by_id (JcatFile *self, const gchar *id, GError **error)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (JCAT_IS_FILE (self), NULL);
	g_return_val_if_fail (id != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* exact ID match */
	for (guint i = 0; i < priv->items->len; i++) {
		JcatItem *item = g_ptr_array_index (priv->items, i);
		if (g_strcmp0 (jcat_item_get_id (item), id) == 0)
			return g_object_ref (item);
	}

	/* try aliases this time */
	for (guint i = 0; i < priv->items->len; i++) {
		JcatItem *item = g_ptr_array_index (priv->items, i);
		g_autoptr(GPtrArray) alias_ids = jcat_item_get_alias_ids (item);
		for (guint j = 0; j < alias_ids->len; j++) {
			const gchar *id_tmp = g_ptr_array_index (alias_ids, j);
			if (g_strcmp0 (id_tmp, id) == 0)
				return g_object_ref (item);
		}
	}

	/* failed */
	g_set_error (error,
		     G_IO_ERROR,
		     G_IO_ERROR_NOT_FOUND,
		     "failed to find %s", id);
	return NULL;
}

/**
 * jcat_file_get_item_default:
 * @self: #JcatFile
 * @error: #GError, or %NULL
 *
 * Finds the default item. If more than one #JcatItem exists this function will
 * return with an error.
 *
 * Returns: (transfer full): a #JcatItem, or %NULL if no default exists
 *
 * Since: 0.1.0
 **/
JcatItem *
jcat_file_get_item_default (JcatFile *self, GError **error)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (JCAT_IS_FILE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* sanity check */
	if (priv->items->len == 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_FOUND,
				     "no items found");
		return NULL;
	}
	if (priv->items->len > 1) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "multiple items found, no default possible");
		return NULL;
	}

	/* only one possible */
	return g_object_ref (g_ptr_array_index (priv->items, 0));
}

/**
 * jcat_file_add_item:
 * @self: #JcatFile
 * @item: #JcatItem
 *
 * Adds an item to a file.
 *
 * Since: 0.1.0
 **/
void
jcat_file_add_item (JcatFile *self, JcatItem *item)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	g_return_if_fail (JCAT_IS_FILE (self));
	g_return_if_fail (JCAT_IS_ITEM (item));
	g_ptr_array_add (priv->items, g_object_ref (item));
}

/**
 * jcat_file_get_version_major:
 * @self: #JcatFile
 *
 * Returns the major version number of the Jcat specification
 *
 * Returns: integer
 *
 * Since: 0.1.0
 **/
guint32
jcat_file_get_version_major (JcatFile *self)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_FILE (self), 0);
	return priv->version_major;
}

/**
 * jcat_file_get_version_minor:
 * @self: #JcatFile
 *
 * Returns the minor version number of the Jcat specification
 *
 * Returns: integer
 *
 * Since: 0.1.0
 **/
guint32
jcat_file_get_version_minor (JcatFile *self)
{
	JcatFilePrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_FILE (self), 0);
	return priv->version_minor;
}

/**
 * jcat_file_new:
 *
 * Creates a new file.
 *
 * Returns: a #JcatFile
 *
 * Since: 0.1.0
 **/
JcatFile *
jcat_file_new (void)
{
	JcatFile *self = g_object_new (JCAT_TYPE_FILE, NULL);
	JcatFilePrivate *priv = GET_PRIVATE (self);
	priv->version_major = 0;
	priv->version_minor = 1;
	return self;
}
