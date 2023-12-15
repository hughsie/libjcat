/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-compile.h"

#define JCAT_TYPE_BLOB jcat_blob_get_type()

G_DECLARE_DERIVABLE_TYPE(JcatBlob, jcat_blob, JCAT, BLOB, GObject)

/**
 * JcatBlobKind:
 * @JCAT_BLOB_KIND_UNKNOWN:		No known blob kind
 * @JCAT_BLOB_KIND_SHA256:		SHA-256 checksum
 * @JCAT_BLOB_KIND_GPG:			GPG detached signature
 * @JCAT_BLOB_KIND_PKCS7:		PKCS-7 detached signature
 * @JCAT_BLOB_KIND_SHA1:		SHA-1 checksum
 * @JCAT_BLOB_KIND_BT_MANIFEST:		Binary transparency manifest
 * @JCAT_BLOB_KIND_BT_CHECKPOINT:	Binary transparency checkpoint
 * @JCAT_BLOB_KIND_BT_INCLUSION_PROOF:	Binary transparency inclusion proof
 * @JCAT_BLOB_KIND_BT_VERIFIER:		Binary transparency verifier
 * @JCAT_BLOB_KIND_ED25519:		ED25519 signature
 * @JCAT_BLOB_KIND_SHA512:		SHA-512 checksum
 *
 * The kind of blob stored as a signature on the item.
 **/
typedef enum {
	JCAT_BLOB_KIND_UNKNOWN,
	JCAT_BLOB_KIND_SHA256,
	JCAT_BLOB_KIND_GPG,
	JCAT_BLOB_KIND_PKCS7,
	JCAT_BLOB_KIND_SHA1,
	JCAT_BLOB_KIND_BT_MANIFEST,	   /* Since: 0.1.9 */
	JCAT_BLOB_KIND_BT_CHECKPOINT,	   /* Since: 0.1.9 */
	JCAT_BLOB_KIND_BT_INCLUSION_PROOF, /* Since: 0.1.9 */
	JCAT_BLOB_KIND_BT_VERIFIER,	   /* Since: 0.1.9 */
	JCAT_BLOB_KIND_ED25519,		   /* Since: 0.1.9 */
	JCAT_BLOB_KIND_SHA512,		   /* Since: 0.1.13 */
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
	JCAT_BLOB_FLAG_NONE = 0,
	JCAT_BLOB_FLAG_IS_UTF8 = 1 << 0,
	/*< private >*/
	JCAT_BLOB_FLAG_LAST
} JcatBlobFlags;

struct _JcatBlobClass {
	GObjectClass parent_class;
	gpointer padding[15];
};

JcatBlobKind
jcat_blob_kind_from_string(const gchar *kind);
const gchar *
jcat_blob_kind_to_string(JcatBlobKind kind);
const gchar *
jcat_blob_kind_to_filename_ext(JcatBlobKind kind);

JcatBlob *
jcat_blob_new(JcatBlobKind kind, GBytes *data) G_GNUC_NON_NULL(2);
JcatBlob *
jcat_blob_new_full(JcatBlobKind kind, GBytes *data, JcatBlobFlags flags) G_GNUC_NON_NULL(2);
JcatBlob *
jcat_blob_new_utf8(JcatBlobKind kind, const gchar *data) G_GNUC_NON_NULL(2);
gchar *
jcat_blob_to_string(JcatBlob *self) G_GNUC_NON_NULL(1);
GBytes *
jcat_blob_get_data(JcatBlob *self) G_GNUC_NON_NULL(1);
gchar *
jcat_blob_get_data_as_string(JcatBlob *self) G_GNUC_NON_NULL(1);
JcatBlobKind
jcat_blob_get_kind(JcatBlob *self) G_GNUC_NON_NULL(1);
JcatBlobKind
jcat_blob_get_target(JcatBlob *self) G_GNUC_NON_NULL(1);
void
jcat_blob_set_target(JcatBlob *self, JcatBlobKind target) G_GNUC_NON_NULL(1);
gint64
jcat_blob_get_timestamp(JcatBlob *self) G_GNUC_NON_NULL(1);
void
jcat_blob_set_timestamp(JcatBlob *self, gint64 timestamp) G_GNUC_NON_NULL(1);
const gchar *
jcat_blob_get_appstream_id(JcatBlob *self) G_GNUC_NON_NULL(1);
void
jcat_blob_set_appstream_id(JcatBlob *self, const gchar *appstream_id) G_GNUC_NON_NULL(1);
