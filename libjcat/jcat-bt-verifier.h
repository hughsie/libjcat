/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-compile.h"

#define JCAT_TYPE_BT_VERIFIER (jcat_bt_verifier_get_type())

G_DECLARE_FINAL_TYPE(JcatBtVerifier, jcat_bt_verifier, JCAT, BT_VERIFIER, GObject)

JcatBtVerifier *
jcat_bt_verifier_new(GBytes *blob, GError **error);
gchar *
jcat_bt_verifier_to_string(JcatBtVerifier *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_bt_verifier_get_name(JcatBtVerifier *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_bt_verifier_get_hash(JcatBtVerifier *self) G_GNUC_NON_NULL(1);
GBytes *
jcat_bt_verifier_get_key(JcatBtVerifier *self) G_GNUC_NON_NULL(1);
guint8
jcat_bt_verifier_get_alg(JcatBtVerifier *self) G_GNUC_NON_NULL(1);
