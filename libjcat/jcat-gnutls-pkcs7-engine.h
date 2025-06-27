/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_GNUTLS_PKCS7_ENGINE (jcat_gnutls_pkcs7_engine_get_type())

G_DECLARE_FINAL_TYPE(JcatGnutlsPkcs7Engine,
		     jcat_gnutls_pkcs7_engine,
		     JCAT,
		     GNUTLS_PKCS7_ENGINE,
		     JcatEngine)

JcatEngine *
jcat_gnutls_pkcs7_engine_new(JcatContext *context) G_GNUC_NON_NULL(1);
