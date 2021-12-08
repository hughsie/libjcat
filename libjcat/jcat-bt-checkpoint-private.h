/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-bt-checkpoint.h"

void
jcat_bt_checkpoint_add_string(JcatBtCheckpoint *self, guint idt, GString *str);
