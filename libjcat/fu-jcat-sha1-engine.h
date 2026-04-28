/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-jcat-context.h"
#include "fu-jcat-engine.h"

#define FU_TYPE_JCAT_SHA1_ENGINE (fu_jcat_sha1_engine_get_type())
G_DECLARE_FINAL_TYPE(FwupdJcatSha1Engine, fu_jcat_sha1_engine, FU, JCAT_SHA1_ENGINE, FuJcatEngine)

FuJcatEngine *
fu_jcat_sha1_engine_new(FuJcatContext *context) G_GNUC_NON_NULL(1);
