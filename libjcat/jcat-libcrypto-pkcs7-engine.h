/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2025 Colin Kinloch <colin.kinloch@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_PKCS7_ENGINE (jcat_libcrypto_pkcs7_engine_get_type())

G_DECLARE_FINAL_TYPE(JcatLibcryptoPkcs7Engine,
		     jcat_libcrypto_pkcs7_engine,
		     JCAT,
		     LIBCRYPTO_PKCS7_ENGINE,
		     JcatEngine)

JcatEngine *
jcat_libcrypto_pkcs7_engine_new(JcatContext *context) G_GNUC_NON_NULL(1);
