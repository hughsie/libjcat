/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_SHA1_ENGINE (jcat_sha1_engine_get_type ())

G_DECLARE_FINAL_TYPE (JcatSha1Engine, jcat_sha1_engine, JCAT, SHA1_ENGINE, JcatEngine)

JcatEngine	*jcat_sha1_engine_new		(JcatContext	*context);
