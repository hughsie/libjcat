/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_PKCS7_ENGINE (jcat_pkcs7_engine_get_type ())

G_DECLARE_FINAL_TYPE (JcatPkcs7Engine, jcat_pkcs7_engine, JCAT, PKCS7_ENGINE, JcatEngine)

JcatEngine	*jcat_pkcs7_engine_new		(JcatContext	*context);
