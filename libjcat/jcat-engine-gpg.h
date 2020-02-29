/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

#define JCAT_TYPE_ENGINE_GPG (jcat_engine_gpg_get_type ())

G_DECLARE_FINAL_TYPE (JcatEngineGpg, jcat_engine_gpg, JCAT, ENGINE_GPG, JcatEngine)

JcatEngine	*jcat_engine_gpg_new		(void);
