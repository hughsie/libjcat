/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_SHA256_ENGINE (jcat_sha256_engine_get_type ())

G_DECLARE_FINAL_TYPE (JcatSha256Engine, jcat_sha256_engine, JCAT, SHA256_ENGINE, JcatEngine)

JcatEngine	*jcat_sha256_engine_new		(JcatContext	*context);
