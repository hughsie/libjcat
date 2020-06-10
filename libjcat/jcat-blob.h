/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#define JCAT_TYPE_BLOB jcat_blob_get_type()

G_DECLARE_DERIVABLE_TYPE(JcatBlob, jcat_blob, JCAT, BLOB, GObject)

/**
 * JcatBlobKind:
 * @JCAT_BLOB_KIND_UNKNOWN:		No known blob kind
 * @JCAT_BLOB_KIND_SHA256:		SHA-256 checksum
 * @JCAT_BLOB_KIND_GPG:			GPG detached signature
 * @JCAT_BLOB_KIND_PKCS7:		PKCS-7 detached signature
 * @JCAT_BLOB_KIND_SHA1:		SHA-1 checksum
 *
 * The kind of blob stored as a signature on the item.
 **/
typedef enum {
	JCAT_BLOB_KIND_UNKNOWN,
	JCAT_BLOB_KIND_SHA256,
	JCAT_BLOB_KIND_GPG,
	JCAT_BLOB_KIND_PKCS7,
	JCAT_BLOB_KIND_SHA1,
	/*< private >*/
	JCAT_BLOB_KIND_LAST
} JcatBlobKind;

/**
 * JcatBlobMethod:
 * @JCAT_BLOB_METHOD_UNKNOWN:		Unknown
 * @JCAT_BLOB_METHOD_CHECKSUM:		Checksum
 * @JCAT_BLOB_METHOD_SIGNATURE:		Signature
 *
 * The blob verification method.
 **/
typedef enum {
	JCAT_BLOB_METHOD_UNKNOWN,
	JCAT_BLOB_METHOD_CHECKSUM,
	JCAT_BLOB_METHOD_SIGNATURE,
	/*< private >*/
	JCAT_BLOB_METHOD_LAST
} JcatBlobMethod;

/**
 * JcatBlobFlags:
 * @JCAT_BLOB_FLAG_NONE:		Generic binary data
 * @JCAT_BLOB_FLAG_IS_UTF8:		ASCII text
 *
 * Flags used when creating the blob.
 **/
typedef enum {
	JCAT_BLOB_FLAG_NONE		= 0,
	JCAT_BLOB_FLAG_IS_UTF8		= 1 << 0,
	/*< private >*/
	JCAT_BLOB_FLAG_LAST
} JcatBlobFlags;

struct _JcatBlobClass
{
	GObjectClass		 parent_class;
	gpointer		 padding[15];
};

JcatBlobKind	 jcat_blob_kind_from_string		(const gchar	*kind);
const gchar	*jcat_blob_kind_to_string		(JcatBlobKind	 kind);
const gchar	*jcat_blob_kind_to_filename_ext		(JcatBlobKind	 kind);

JcatBlob	*jcat_blob_new				(JcatBlobKind	 kind,
							 GBytes		*data);
JcatBlob	*jcat_blob_new_full			(JcatBlobKind	 kind,
							 GBytes		*data,
							 JcatBlobFlags	 flags);
JcatBlob	*jcat_blob_new_utf8			(JcatBlobKind	 kind,
							 const gchar	*data);
gchar		*jcat_blob_to_string 			(JcatBlob	*self);
GBytes		*jcat_blob_get_data			(JcatBlob	*self);
gchar		*jcat_blob_get_data_as_string		(JcatBlob	*self);
JcatBlobKind	 jcat_blob_get_kind			(JcatBlob	*self);
gint64		 jcat_blob_get_timestamp		(JcatBlob	*self);
void		 jcat_blob_set_timestamp		(JcatBlob	*self,
							 gint64		 timestamp);
const gchar	*jcat_blob_get_appstream_id		(JcatBlob	*self);
void		 jcat_blob_set_appstream_id		(JcatBlob	*self,
							 const gchar	*appstream_id);
