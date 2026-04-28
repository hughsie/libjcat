/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

/**
 * FuJcatVerifyFlags:
 * @FU_JCAT_VERIFY_FLAG_NONE:			No flags set
 * @FU_JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS:	Disable checking of validity periods
 * @FU_JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM:		Require the item contains at least one
 * checksum
 * @FU_JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE:		Require the item contains at least one
 * signature
 * @FU_JCAT_VERIFY_FLAG_ONLY_PQ:			Only consider post-quantum signatures
 *
 * The flags to use when interacting with a keyring
 **/
typedef enum {
	FU_JCAT_VERIFY_FLAG_NONE = 0,
	FU_JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS = 1 << 2,
	FU_JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM = 1 << 3,
	FU_JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE = 1 << 4,
	FU_JCAT_VERIFY_FLAG_ONLY_PQ = 1 << 5,
	/*< private >*/
	FU_JCAT_VERIFY_FLAG_LAST
} FuJcatVerifyFlags;

/**
 * FuJcatSignFlags:
 * @FU_JCAT_VERIFY_FLAG_NONE:			No flags set
 * @FU_JCAT_VERIFY_FLAG_ADD_TIMESTAMP:		Add a timestamp
 * @FU_JCAT_VERIFY_FLAG_ADD_CERT: 			Add a certificate
 * @FU_JCAT_VERIFY_FLAG_USE_PQ: 			Use post-quantum algorithm
 *
 * The flags to when signing a binary
 **/
typedef enum {
	FU_JCAT_VERIFY_FLAG_NONE = 0,
	FU_JCAT_VERIFY_FLAG_ADD_TIMESTAMP = 1 << 0,
	FU_JCAT_VERIFY_FLAG_ADD_CERT = 1 << 1,
	FU_JCAT_VERIFY_FLAG_USE_PQ = 1 << 2,
	/*< private >*/
	FU_JCAT_VERIFY_FLAG_LAST
} FuJcatSignFlags;

gboolean
fu_bytes_set_contents_full(const gchar *filename, GBytes *bytes, gint mode, GError **error)
    G_GNUC_NON_NULL(1, 2);
