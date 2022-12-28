/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_SHA512_ENGINE (jcat_sha512_engine_get_type())

G_DECLARE_FINAL_TYPE(JcatSha512Engine, jcat_sha512_engine, JCAT, SHA512_ENGINE, JcatEngine)

JcatEngine *
jcat_sha512_engine_new(JcatContext *context);
