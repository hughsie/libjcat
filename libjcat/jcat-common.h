/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

/**
 * JcatImportFlags:
 * @JCAT_IMPORT_FLAG_NONE:			No flags set
 *
 * Flags used for importing.
 **/
typedef enum {
	JCAT_IMPORT_FLAG_NONE		= 0,
	/*< private >*/
	JCAT_IMPORT_FLAG_LAST
} JcatImportFlags;

/**
 * JcatExportFlags:
 * @JCAT_EXPORT_FLAG_NONE:			No flags set
 * @JCAT_EXPORT_FLAG_NO_TIMESTAMP:		Do not export timestamps
 *
 * Flags used for exporting.
 **/
typedef enum {
	JCAT_EXPORT_FLAG_NONE		= 0,
	JCAT_EXPORT_FLAG_NO_TIMESTAMP	= 1 << 1,
	/*< private >*/
	JCAT_EXPORT_FLAG_LAST
} JcatExportFlags;

/**
 * JcatVerifyFlags:
 * @JCAT_VERIFY_FLAG_NONE:			No flags set
 * @JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS:	Disable checking of validity periods
 * @JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM:		Require that the #JcatItem contains at least one checksum
 * @JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE:		Require that the #JcatItem contains at least one signature
 *
 * The flags to use when interacting with a keyring
 **/
typedef enum {
	JCAT_VERIFY_FLAG_NONE			= 0,
	JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS	= 1 << 2,
	JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM	= 1 << 3,
	JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE	= 1 << 4,
	/*< private >*/
	JCAT_VERIFY_FLAG_LAST
} JcatVerifyFlags;

/**
 * JcatSignFlags:
 * @JCAT_SIGN_FLAG_NONE:			No flags set
 * @JCAT_SIGN_FLAG_ADD_TIMESTAMP:		Add a timestamp
 * @JCAT_SIGN_FLAG_ADD_CERT: 			Add a certificate
 *
 * The flags to when signing a binary
 **/
typedef enum {
	JCAT_SIGN_FLAG_NONE			= 0,
	JCAT_SIGN_FLAG_ADD_TIMESTAMP		= 1 << 0,
	JCAT_SIGN_FLAG_ADD_CERT			= 1 << 1,
	/*< private >*/
	JCAT_SIGN_FLAG_LAST
} JcatSignFlags;
