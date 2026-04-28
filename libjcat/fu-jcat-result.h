/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fwupd-jcat-blob.h"

#define FU_TYPE_JCAT_RESULT (fwupd_jcat_result_get_type())
G_DECLARE_FINAL_TYPE(FuJcatResult, fwupd_jcat_result, FU, JCAT_RESULT, GObject)

gchar *
fwupd_jcat_result_to_string(FuJcatResult *self) G_GNUC_NON_NULL(1);
gint64
fwupd_jcat_result_get_timestamp(FuJcatResult *self) G_GNUC_NON_NULL(1);
const gchar *
fwupd_jcat_result_get_authority(FuJcatResult *self) G_GNUC_NON_NULL(1);
FwupdJcatBlobKind
fwupd_jcat_result_get_kind(FuJcatResult *self) G_GNUC_NON_NULL(1);
FwupdJcatBlobMethod
fwupd_jcat_result_get_method(FuJcatResult *self) G_GNUC_NON_NULL(1);
void
fwupd_jcat_result_add_string(FuJcatResult *self, guint idt, GString *str) G_GNUC_NON_NULL(1, 3);
FuJcatEngine *
fwupd_jcat_result_get_engine(FuJcatResult *self) G_GNUC_NON_NULL(1);
