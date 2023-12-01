/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-compile.h"

#define JCAT_TYPE_BT_CHECKPOINT (jcat_bt_checkpoint_get_type())

G_DECLARE_FINAL_TYPE(JcatBtCheckpoint, jcat_bt_checkpoint, JCAT, BT_CHECKPOINT, GObject)

JcatBtCheckpoint *
jcat_bt_checkpoint_new(GBytes *blob, GError **error);
gchar *
jcat_bt_checkpoint_to_string(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_bt_checkpoint_get_origin(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_bt_checkpoint_get_identity(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_bt_checkpoint_get_hash(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
GBytes *
jcat_bt_checkpoint_get_pubkey(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
GBytes *
jcat_bt_checkpoint_get_signature(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
GBytes *
jcat_bt_checkpoint_get_payload(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
guint
jcat_bt_checkpoint_get_log_size(JcatBtCheckpoint *self) G_GNUC_NON_NULL(1);
