/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

#define JCAT_TYPE_ENGINE_PKCS7 (jcat_engine_pkcs7_get_type ())

G_DECLARE_FINAL_TYPE (JcatEnginePkcs7, jcat_engine_pkcs7, JCAT, ENGINE_PKCS7, JcatEngine)

JcatEngine	*jcat_engine_pkcs7_new		(void);
