/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

typedef enum {
	JCAT_ENGINE_VERIFY_KIND_UNKNOWN,
	JCAT_ENGINE_VERIFY_KIND_CHECKSUM,
	JCAT_ENGINE_VERIFY_KIND_SIGNATURE,
	JCAT_ENGINE_VERIFY_KIND_LAST
} JcatEngineVerifyKind;

JcatBlobKind	 jcat_engine_get_kind			(JcatEngine	*self);
JcatEngineVerifyKind jcat_engine_get_verify_kind	(JcatEngine	*self);
const gchar	*jcat_engine_get_localstatedir		(JcatEngine	*self);
void		 jcat_engine_add_string			(JcatEngine	*self,
							 guint		 idt,
							 GString	*str);
gchar		*jcat_engine_to_string 			(JcatEngine	*self);
