/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"
#include "jcat-result.h"

void
jcat_result_add_string(JcatResult *self, guint idt, GString *str) G_GNUC_NON_NULL(1, 3);
JcatEngine *
jcat_result_get_engine(JcatResult *self) G_GNUC_NON_NULL(1);
