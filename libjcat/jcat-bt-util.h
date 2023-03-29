/*
 * Copyright (C) 2023 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

gboolean
jcat_bt_generate_key_pair(const gchar *keyname,
			  GBytes **public_key,
			  GBytes **private_key,
			  GError **error);
