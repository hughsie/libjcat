/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_GPG_ENGINE (jcat_gpg_engine_get_type ())

G_DECLARE_FINAL_TYPE (JcatGpgEngine, jcat_gpg_engine, JCAT, GPG_ENGINE, JcatEngine)

JcatEngine	*jcat_gpg_engine_new		(JcatContext	*context);
