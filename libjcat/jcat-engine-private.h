/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-engine.h"

const gchar *
jcat_engine_get_keyring_path(JcatEngine *self) G_GNUC_NON_NULL(1);
void
jcat_engine_add_string(JcatEngine *self, guint idt, GString *str) G_GNUC_NON_NULL(1, 3);
gchar *
jcat_engine_to_string(JcatEngine *self) G_GNUC_NON_NULL(1);
