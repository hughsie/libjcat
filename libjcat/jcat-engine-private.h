/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

const gchar	*jcat_engine_get_keyring_path		(JcatEngine	*self);
void		 jcat_engine_add_string			(JcatEngine	*self,
							 guint		 idt,
							 GString	*str);
gchar		*jcat_engine_to_string 			(JcatEngine	*self);
