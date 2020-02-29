/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

#define JCAT_TYPE_ENGINE_SHA256 (jcat_engine_sha256_get_type ())

G_DECLARE_FINAL_TYPE (JcatEngineSha256, jcat_engine_sha256, JCAT, ENGINE_SHA256, JcatEngine)

JcatEngine	*jcat_engine_sha256_new		(void);
