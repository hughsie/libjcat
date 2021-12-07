/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_ED25519_ENGINE (jcat_ed25519_engine_get_type())

G_DECLARE_FINAL_TYPE(JcatEd25519Engine, jcat_ed25519_engine, JCAT, ED25519_ENGINE, JcatEngine)

JcatEngine *
jcat_ed25519_engine_new(JcatContext *context);
