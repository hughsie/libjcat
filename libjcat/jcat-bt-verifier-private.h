/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-bt-verifier.h"

void
jcat_bt_verifier_add_string(JcatBtVerifier *self, guint idt, GString *str) G_GNUC_NON_NULL(1, 3);
