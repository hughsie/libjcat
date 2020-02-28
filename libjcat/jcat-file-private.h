/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-file.h"

void		 jcat_file_add_string			(JcatFile	*self,
							 guint		 idt,
							 GString	*str);
