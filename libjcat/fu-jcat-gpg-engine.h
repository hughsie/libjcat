/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-jcat-context.h"
#include "fu-jcat-engine.h"

#define FU_TYPE_JCAT_GPG_ENGINE (fu_jcat_gpg_engine_get_type())
G_DECLARE_FINAL_TYPE(FuJcatGpgEngine, fu_jcat_gpg_engine, FU, JCAT_GPG_ENGINE, FuJcatEngine)

FuJcatEngine *
fu_jcat_gpg_engine_new(FuJcatContext *context) G_GNUC_NON_NULL(1);
