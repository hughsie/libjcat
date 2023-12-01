/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "jcat-blob.h"

#define JCAT_TYPE_RESULT (jcat_result_get_type())

G_DECLARE_FINAL_TYPE(JcatResult, jcat_result, JCAT, RESULT, GObject)

gchar *
jcat_result_to_string(JcatResult *self) G_GNUC_NON_NULL(1);
gint64
jcat_result_get_timestamp(JcatResult *self) G_GNUC_NON_NULL(1);
const gchar *
jcat_result_get_authority(JcatResult *self) G_GNUC_NON_NULL(1);
JcatBlobKind
jcat_result_get_kind(JcatResult *self) G_GNUC_NON_NULL(1);
JcatBlobMethod
jcat_result_get_method(JcatResult *self) G_GNUC_NON_NULL(1);
