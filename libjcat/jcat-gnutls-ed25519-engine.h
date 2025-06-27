/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-context.h"
#include "jcat-engine.h"

#define JCAT_TYPE_GNUTLS_GNUTLS_ED25519_ENGINE (jcat_gnutls_ed25519_engine_get_type())

G_DECLARE_FINAL_TYPE(JcatGnutlsEd25519Engine,
		     jcat_gnutls_ed25519_engine,
		     JCAT,
		     GNUTLS_ED25519_ENGINE,
		     JcatEngine)

JcatEngine *
jcat_gnutls_ed25519_engine_new(JcatContext *context) G_GNUC_NON_NULL(1);
