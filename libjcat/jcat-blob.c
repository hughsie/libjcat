/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-blob-private.h"

typedef struct {
	JcatBlobKind		 kind;
	JcatBlobFlags		 flags;
	GBytes			*data;
	gchar			*appstream_id;
	gint64			 timestamp;
} JcatBlobPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (JcatBlob, jcat_blob, G_TYPE_OBJECT)
#define GET_PRIVATE(o) (jcat_blob_get_instance_private (o))

static void
jcat_blob_finalize (GObject *obj)
{
	JcatBlob *self = JCAT_BLOB (obj);
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_free (priv->appstream_id);
	g_bytes_unref (priv->data);
	G_OBJECT_CLASS (jcat_blob_parent_class)->finalize (obj);
}

static void
jcat_blob_class_init (JcatBlobClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = jcat_blob_finalize;
}

static void
jcat_blob_init (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	priv->timestamp = g_get_real_time () / G_USEC_PER_SEC;
}

/**
 * jcat_blob_kind_from_string:
 * @kind: A string
 *
 * Converts the string to an enumerated kind.
 *
 * Returns: a #JcatBlobKind, or %JCAT_BLOB_KIND_UNKNOWN if the kind was not found
 *
 * Since: 0.1.0
 **/
JcatBlobKind
jcat_blob_kind_from_string (const gchar *kind)
{
	if (g_strcmp0 (kind, "gpg") == 0)
		return JCAT_BLOB_KIND_GPG;
	if (g_strcmp0 (kind, "pkcs7") == 0)
		return JCAT_BLOB_KIND_PKCS7;
	if (g_strcmp0 (kind, "sha256") == 0)
		return JCAT_BLOB_KIND_SHA256;
	if (g_strcmp0 (kind, "sha1") == 0)
		return JCAT_BLOB_KIND_SHA1;
	return JCAT_BLOB_KIND_UNKNOWN;
}

/**
 * jcat_blob_kind_to_string:
 * @kind: #JcatBlobKind
 *
 * Converts the enumerated kind to a string.
 *
 * Returns: a string, or %NULL if the kind was not found
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_blob_kind_to_string (JcatBlobKind kind)
{
	if (kind == JCAT_BLOB_KIND_GPG)
		return "gpg";
	if (kind == JCAT_BLOB_KIND_PKCS7)
		return "pkcs7";
	if (kind == JCAT_BLOB_KIND_SHA256)
		return "sha256";
	if (kind == JCAT_BLOB_KIND_SHA1)
		return "sha1";
	return NULL;
}

/**
 * jcat_blob_kind_to_filename_ext:
 * @kind: #JcatBlobKind
 *
 * Converts the enumerated kind to the normal file extension.
 *
 * Returns: a string, or %NULL if the kind was not found
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_blob_kind_to_filename_ext (JcatBlobKind kind)
{
	if (kind == JCAT_BLOB_KIND_GPG)
		return "asc";
	if (kind == JCAT_BLOB_KIND_PKCS7)
		return "p7b";
	if (kind == JCAT_BLOB_KIND_SHA256)
		return "sha256";
	if (kind == JCAT_BLOB_KIND_SHA1)
		return "sha1";
	return NULL;
}

/* private */
void
jcat_blob_add_string (JcatBlob *self, guint idt, GString *str)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	jcat_string_append_kv (str, idt, G_OBJECT_TYPE_NAME (self), NULL);
	jcat_string_append_kv (str, idt + 1, "Kind",
			       jcat_blob_kind_to_string (priv->kind));
	jcat_string_append_kv (str, idt + 1, "Flags",
			       priv->flags & JCAT_BLOB_FLAG_IS_UTF8 ? "is-utf8" : "none");
	if (priv->appstream_id != NULL)
		jcat_string_append_kv (str, idt + 1, "AppstreamId", priv->appstream_id);
	if (priv->timestamp != 0) {
		g_autoptr(GDateTime) dt = g_date_time_new_from_unix_utc (priv->timestamp);
#if GLIB_CHECK_VERSION(2,62,0)
		g_autofree gchar *tmp = g_date_time_format_iso8601 (dt);
#else
		g_autofree gchar *tmp = g_date_time_format (dt, "%FT%TZ");
#endif
		jcat_string_append_kv (str, idt + 1, "Timestamp", tmp);
	}
	if (priv->data != NULL) {
		g_autofree gchar *tmp = jcat_blob_get_data_as_string (self);
		g_autofree gchar *size = g_strdup_printf ("0x%x", (guint) g_bytes_get_size (priv->data));
		jcat_string_append_kv (str, idt + 1, "Size", size);
		jcat_string_append_kv (str, idt + 1, "Data", tmp);
	}
}

/**
 * jcat_blob_to_string:
 * @self: #JcatBlob
 *
 * Converts the #JcatBlob to a string.
 *
 * Returns: string
 *
 * Since: 0.1.0
 **/
gchar *
jcat_blob_to_string (JcatBlob *self)
{
	GString *str = g_string_new (NULL);
	jcat_blob_add_string (self, 0, str);
	return g_string_free (str, FALSE);
}

/* private */
JcatBlob *
jcat_blob_import (JsonObject *obj, JcatImportFlags flags, GError **error)
{
	const gchar *data_str;
	const gchar *required[] = { "Kind", "Data", "Flags", NULL };
	g_autoptr(JcatBlob) self = g_object_new (JCAT_TYPE_BLOB, NULL);
	JcatBlobPrivate *priv = GET_PRIVATE (self);

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

	/* get kind, which can be unknown to us for forward compat */
	priv->kind = json_object_get_int_member (obj, "Kind");
	priv->flags = json_object_get_int_member (obj, "Flags");

	/* both optional */
	if (json_object_has_member (obj, "Timestamp"))
		priv->timestamp = json_object_get_int_member (obj, "Timestamp");
	if (json_object_has_member (obj, "AppstreamId"))
		priv->appstream_id = g_strdup (json_object_get_string_member (obj, "AppstreamId"));

	/* get compressed data */
	data_str = json_object_get_string_member (obj, "Data");
	if ((priv->flags & JCAT_BLOB_FLAG_IS_UTF8) == 0) {
		gsize bufsz = 0;
		g_autofree guchar *buf = g_base64_decode (data_str, &bufsz);
		priv->data = g_bytes_new_take (g_steal_pointer (&buf), bufsz);
	} else {
		const gchar *tmp = json_object_get_string_member (obj, "Data");
		priv->data = g_bytes_new (tmp, strlen (tmp));
	}

	/* success */
	return g_steal_pointer (&self);
}

void
jcat_blob_export (JcatBlob *self, JcatExportFlags flags, JsonBuilder *builder)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_autofree gchar *data_str = jcat_blob_get_data_as_string (self);

	/* add metadata */
	json_builder_set_member_name (builder, "Kind");
	json_builder_add_int_value (builder, priv->kind);
	json_builder_set_member_name (builder, "Flags");
	json_builder_add_int_value (builder, priv->flags);
	if (priv->appstream_id != NULL) {
		json_builder_set_member_name (builder, "AppstreamId");
		json_builder_add_string_value (builder, priv->appstream_id);
	}
	if (priv->timestamp > 0 && (flags & JCAT_EXPORT_FLAG_NO_TIMESTAMP) == 0) {
		json_builder_set_member_name (builder, "Timestamp");
		json_builder_add_int_value (builder, priv->timestamp);
	}
	json_builder_set_member_name (builder, "Data");
	json_builder_add_string_value (builder, data_str);
}

/**
 * jcat_blob_get_timestamp:
 * @self: #JcatBlob
 *
 * Gets the creation timestamp for the blob.
 *
 * Returns: UTC UNIX time, or 0 if unset
 *
 * Since: 0.1.0
 **/
gint64
jcat_blob_get_timestamp (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_BLOB (self), 0);
	return priv->timestamp;
}

/**
 * jcat_blob_set_timestamp:
 * @self: #JcatBlob
 * @timestamp: UTC timestamp
 *
 * Sets the creation timestamp for the blob.
 *
 * Since: 0.1.0
 **/
void
jcat_blob_set_timestamp (JcatBlob *self, gint64 timestamp)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_if_fail (JCAT_IS_BLOB (self));
	priv->timestamp = timestamp;
}

/**
 * jcat_blob_get_appstream_id:
 * @self: #JcatBlob
 *
 * Gets the optional AppStream ID for the blob.
 *
 * Returns: a string, or %NULL if not set
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_blob_get_appstream_id (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_BLOB (self), NULL);
	return priv->appstream_id;
}

/**
 * jcat_blob_set_appstream_id:
 * @self: #JcatBlob
 * @appstream_id: (nullable): string
 *
 * Sets an optional AppStream ID on the blob.
 *
 * Since: 0.1.0
 **/
void
jcat_blob_set_appstream_id (JcatBlob *self, const gchar *appstream_id)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_if_fail (JCAT_IS_BLOB (self));
	g_free (priv->appstream_id);
	priv->appstream_id = g_strdup (appstream_id);
}

/**
 * jcat_blob_get_data:
 * @self: #JcatBlob
 *
 * Gets the data stored in the blob, typically in binary (unprintable) form.
 *
 * Returns: (transfer none): a #GBytes, or %NULL if the filename was not found
 *
 * Since: 0.1.0
 **/
GBytes *
jcat_blob_get_data (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_BLOB (self), NULL);
	return priv->data;
}

/**
 * jcat_blob_get_data_as_string:
 * @self: #JcatBlob
 *
 * Gets the data stored in the blob, in human readable form.
 *
 * Returns: (transfer full): base64 encoded version of data
 *
 * Since: 0.1.0
 **/
gchar *
jcat_blob_get_data_as_string (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	gsize bufsz = 0;
	const guchar *buf = g_bytes_get_data (priv->data, &bufsz);

	g_return_val_if_fail (JCAT_IS_BLOB (self), NULL);

	/* may be binary data or not NULL terminated */
	if ((priv->flags & JCAT_BLOB_FLAG_IS_UTF8) == 0)
		return g_base64_encode (buf, bufsz);
	return g_strndup ((const gchar *) buf, bufsz);
}

/**
 * jcat_blob_get_kind:
 * @self: #JcatBlob
 *
 * gets the blob kind
 *
 * Returns: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 *
 * Since: 0.1.0
 **/
JcatBlobKind
jcat_blob_get_kind (JcatBlob *self)
{
	JcatBlobPrivate *priv = GET_PRIVATE (self);
	g_return_val_if_fail (JCAT_IS_BLOB (self), 0);
	return priv->kind;
}

/**
 * jcat_blob_new_full:
 * @kind: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 * @data: #GBytes
 * @flags: #JcatBlobFlags
 *
 * Creates a new blob.
 *
 * Returns: a #JcatBlob
 *
 * Since: 0.1.0
 **/
JcatBlob *
jcat_blob_new_full (JcatBlobKind kind, GBytes *data, JcatBlobFlags flags)
{
	JcatBlob *self = g_object_new (JCAT_TYPE_BLOB, NULL);
	JcatBlobPrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (data != NULL, NULL);

	priv->kind = kind;
	priv->data = g_bytes_ref (data);
	priv->flags = flags;
	return self;
}

/**
 * jcat_blob_new:
 * @kind: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 * @data: #GBytes
 *
 * Creates a new blob.
 *
 * Returns: a #JcatBlob
 *
 * Since: 0.1.0
 **/
JcatBlob *
jcat_blob_new (JcatBlobKind kind, GBytes *data)
{
	return jcat_blob_new_full (kind, data, JCAT_BLOB_FLAG_NONE);
}

/**
 * jcat_blob_new_utf8:
 * @kind: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 * @data: ASCII data
 *
 * Creates a new ASCII blob.
 *
 * Returns: a #JcatBlob
 *
 * Since: 0.1.0
 **/
JcatBlob *
jcat_blob_new_utf8 (JcatBlobKind kind, const gchar *data)
{
	JcatBlob *self = g_object_new (JCAT_TYPE_BLOB, NULL);
	JcatBlobPrivate *priv = GET_PRIVATE (self);

	g_return_val_if_fail (data != NULL, NULL);

	priv->flags = JCAT_BLOB_FLAG_IS_UTF8;
	priv->kind = kind;
	priv->data = g_bytes_new (data, strlen (data));
	return self;
}
