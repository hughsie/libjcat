/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-common-private.h"
#include "jcat-engine-private.h"
#include "jcat-result-private.h"

struct _JcatResult
{
	GObject			 parent_instance;
	gint64			 timestamp;
	gchar			*authority;
	JcatEngine		*engine;
};

G_DEFINE_TYPE (JcatResult, jcat_result, G_TYPE_OBJECT)

enum {
	PROP_0,
	PROP_ENGINE,
	PROP_TIMESTAMP,
	PROP_AUTHORITY,
	PROP_LAST
};

/**
 * jcat_result_get_engine:
 * @self: #JcatResult
 *
 * Gets the engine that created this result.
 *
 * Returns: (transfer full): #JcatEngine, or %NULL
 *
 * Since: 0.1.0
 **/
JcatEngine *
jcat_result_get_engine (JcatResult *self)
{
	g_return_val_if_fail (JCAT_IS_RESULT (self), NULL);
	if (self->engine == NULL)
		return NULL;
	return g_object_ref (self->engine);
}

/**
 * jcat_result_get_timestamp:
 * @self: #JcatResult
 *
 * Gets the signing timestamp, if set.
 *
 * Returns: UNIX timestamp, or 0 if unset
 *
 * Since: 0.1.0
 **/
gint64
jcat_result_get_timestamp (JcatResult *self)
{
	g_return_val_if_fail (JCAT_IS_RESULT (self), 0);
	return self->timestamp;
}

/**
 * jcat_result_get_authority:
 * @self: #JcatResult
 *
 * Gets the signing authority, if set.
 *
 * Returns: string, or %NULL
 *
 * Since: 0.1.0
 **/
const gchar *
jcat_result_get_authority (JcatResult *self)
{
	g_return_val_if_fail (JCAT_IS_RESULT (self), NULL);
	return self->authority;
}


/**
 * jcat_result_get_kind:
 * @self: #JcatResult
 *
 * Gets the blob kind.
 *
 * Returns: #JcatBlobKind, e.g. %JCAT_BLOB_KIND_SHA256
 *
 * Since: 0.1.3
 **/
JcatBlobKind
jcat_result_get_kind (JcatResult *self)
{
	if (self->engine == NULL)
		return JCAT_BLOB_KIND_UNKNOWN;
	return jcat_engine_get_kind (self->engine);
}

/**
 * jcat_result_get_method:
 * @self: #JcatResult
 *
 * Gets the verification kind.
 *
 * Returns: #JcatBlobMethod, e.g. %JCAT_BLOB_METHOD_SIGNATURE
 *
 * Since: 0.1.3
 **/
JcatBlobMethod
jcat_result_get_method (JcatResult *self)
{
	if (self->engine == NULL)
		return JCAT_BLOB_METHOD_UNKNOWN;
	return jcat_engine_get_method (self->engine);
}

/* private */
void
jcat_result_add_string (JcatResult *self, guint idt, GString *str)
{
	jcat_string_append_kv (str, idt, G_OBJECT_TYPE_NAME (self), NULL);
	if (self->timestamp != 0) {
		g_autoptr(GDateTime) dt = g_date_time_new_from_unix_utc (self->timestamp);
#if GLIB_CHECK_VERSION(2,62,0)
		g_autofree gchar *tmp = g_date_time_format_iso8601 (dt);
#else
		g_autofree gchar *tmp = g_date_time_format (dt, "%FT%TZ");
#endif
		jcat_string_append_kv (str, idt + 1, "Timestamp", tmp);
	}
	if (self->authority != NULL && self->authority[0] != '\0')
		jcat_string_append_kv (str, idt + 1, "Authority", self->authority);
	if (self->engine != NULL)
		jcat_engine_add_string (self->engine, idt + 1, str);
}

/**
 * jcat_result_to_string:
 * @self: #JcatResult
 *
 * Converts the #JcatResult to a string.
 *
 * Returns: string
 *
 * Since: 0.1.0
 **/
gchar *
jcat_result_to_string (JcatResult *self)
{
	GString *str = g_string_new (NULL);
	jcat_result_add_string (self, 0, str);
	return g_string_free (str, FALSE);
}

static void
jcat_result_finalize (GObject *object)
{
	JcatResult *self = JCAT_RESULT (object);
	if (self->engine != NULL)
		g_object_unref (self->engine);
	g_free (self->authority);
	G_OBJECT_CLASS (jcat_result_parent_class)->finalize (object);
}

static void
jcat_result_get_property (GObject *object, guint prop_id,
				GValue *value, GParamSpec *pspec)
{
	JcatResult *self = JCAT_RESULT (object);
	switch (prop_id) {
	case PROP_ENGINE:
		g_value_set_object (value, self->engine);
		break;
	case PROP_TIMESTAMP:
		g_value_set_int64 (value, self->timestamp);
		break;
	case PROP_AUTHORITY:
		g_value_set_string (value, self->authority);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
jcat_result_set_property (GObject *object, guint prop_id,
				const GValue *value, GParamSpec *pspec)
{
	JcatResult *self = JCAT_RESULT (object);
	switch (prop_id) {
	case PROP_ENGINE:
		g_set_object (&self->engine, g_value_get_object (value));
		break;
	case PROP_TIMESTAMP:
		self->timestamp = g_value_get_int64 (value);
		break;
	case PROP_AUTHORITY:
		self->authority = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
jcat_result_class_init (JcatResultClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GParamSpec *pspec;

	object_class->get_property = jcat_result_get_property;
	object_class->set_property = jcat_result_set_property;
	object_class->finalize = jcat_result_finalize;

	pspec = g_param_spec_object ("engine", NULL, NULL,
				     JCAT_TYPE_ENGINE,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_ENGINE, pspec);

	pspec = g_param_spec_int64 ("timestamp", NULL, NULL,
				    0, G_MAXINT64, 0,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_TIMESTAMP, pspec);

	pspec = g_param_spec_string ("authority", NULL, NULL, NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_NAME);
	g_object_class_install_property (object_class, PROP_AUTHORITY, pspec);
}

static void
jcat_result_init (JcatResult *self)
{
}
