/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-jcat-context.h"
#include "fu-jcat-engine.h"

#define FU_TYPE_JCAT_GNUTLS_GNUTLS_ED25519_ENGINE (fu_jcat_gnutls_ed25519_engine_get_type())
G_DECLARE_FINAL_TYPE(FuJcatGnutlsEd25519Engine,
		     fu_jcat_gnutls_ed25519_engine,
		     FU,
		     JCAT_GNUTLS_ED25519_ENGINE,
		     FuJcatEngine)

FuJcatEngine *
fu_jcat_gnutls_ed25519_engine_new(FuJcatContext *context) G_GNUC_NON_NULL(1);
