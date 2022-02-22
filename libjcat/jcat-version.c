/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-version.h"

/**
 * jcat_version_string:
 *
 * Gets the JCat installed runtime version.
 *
 * Returns: a version number, e.g. "0.1.11"
 *
 * Since: 0.1.11
 **/
const gchar *
jcat_version_string(void)
{
	return G_STRINGIFY(JCAT_MAJOR_VERSION) "." G_STRINGIFY(JCAT_MINOR_VERSION) "." G_STRINGIFY(
	    JCAT_MICRO_VERSION);
}
