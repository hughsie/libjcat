/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-result.h"

void		 jcat_result_add_string		(JcatResult	*self,
						 guint		 idt,
						 GString	*str);
JcatEngine	*jcat_result_get_engine		(JcatResult	*self);
