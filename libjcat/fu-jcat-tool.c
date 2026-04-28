/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#define G_LOG_DOMAIN "FwupdJcat"

#include "config.h"

#include <glib/gi18n.h>
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_GIO_UNIX
#include <glib-unix.h>
#endif

#include "fu-jcat-common.h"
#include "fu-jcat-context.h"
#include "fwupd-jcat-file.h"

typedef struct {
	GCancellable *cancellable;
	GPtrArray *cmd_array;
	FuJcatContext *context;
	gboolean basename;
	gboolean disable_time_checks;
	gboolean only_pq;
	gchar *prefix;
	gchar *appstream_id;
	FwupdJcatBlobKind kind;
	FwupdJcatBlobKind target;
} FwupdJcatToolPrivate;

static void
fwupd_jcat_tool_private_free(FwupdJcatToolPrivate *priv)
{
	if (priv == NULL)
		return;
	g_object_unref(priv->cancellable);
	if (priv->context != NULL)
		g_object_unref(priv->context);
	if (priv->cmd_array != NULL)
		g_ptr_array_unref(priv->cmd_array);
	g_free(priv->appstream_id);
	g_free(priv->prefix);
	g_free(priv);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTOPTR_CLEANUP_FUNC(FwupdJcatToolPrivate, fwupd_jcat_tool_private_free)
#pragma clang diagnostic pop

typedef gboolean (*FuUtilPrivateCb)(FwupdJcatToolPrivate *util, gchar **values, GError **error);

typedef struct {
	gchar *name;
	gchar *arguments;
	gchar *description;
	FuUtilPrivateCb callback;
} FuUtilItem;

static void
fwupd_jcat_tool_item_free(FuUtilItem *item)
{
	g_free(item->name);
	g_free(item->arguments);
	g_free(item->description);
	g_free(item);
}

static gint
fwupd_jcat_tool_sort_command_name_cb(FuUtilItem **item1, FuUtilItem **item2)
{
	return g_strcmp0((*item1)->name, (*item2)->name);
}

static void
fwupd_jcat_tool_add(GPtrArray *array,
		    const gchar *name,
		    const gchar *arguments,
		    const gchar *description,
		    FuUtilPrivateCb callback)
{
	g_auto(GStrv) names = NULL;

	g_return_if_fail(name != NULL);
	g_return_if_fail(description != NULL);
	g_return_if_fail(callback != NULL);

	/* add each one */
	names = g_strsplit(name, ",", -1);
	for (guint i = 0; names[i] != NULL; i++) {
		FuUtilItem *item = g_new0(FuUtilItem, 1);
		item->name = g_strdup(names[i]);
		if (i == 0) {
			item->description = g_strdup(description);
		} else {
			/* TRANSLATORS: this is a command alias, e.g. 'get-devices' */
			item->description = g_strdup_printf(_("Alias to %s"), names[0]);
		}
		item->arguments = g_strdup(arguments);
		item->callback = callback;
		g_ptr_array_add(array, item);
	}
}

static gchar *
fwupd_jcat_tool_get_descriptions(GPtrArray *array)
{
	gsize len;
	const gsize max_len = 31;
	FuUtilItem *item;
	GString *string;

	/* print each command */
	string = g_string_new("");
	for (guint i = 0; i < array->len; i++) {
		item = g_ptr_array_index(array, i);
		g_string_append(string, "  ");
		g_string_append(string, item->name);
		len = strlen(item->name) + 2;
		if (item->arguments != NULL) {
			g_string_append(string, " ");
			g_string_append(string, item->arguments);
			len += strlen(item->arguments) + 1;
		}
		if (len < max_len) {
			for (guint j = len; j < max_len + 1; j++)
				g_string_append_c(string, ' ');
			g_string_append(string, item->description);
			g_string_append_c(string, '\n');
		} else {
			g_string_append_c(string, '\n');
			for (guint j = 0; j < max_len + 1; j++)
				g_string_append_c(string, ' ');
			g_string_append(string, item->description);
			g_string_append_c(string, '\n');
		}
	}

	/* remove trailing newline */
	if (string->len > 0)
		g_string_set_size(string, string->len - 1);

	return g_string_free(string, FALSE);
}

static gboolean
fwupd_jcat_tool_run(FwupdJcatToolPrivate *priv,
		    const gchar *command,
		    gchar **values,
		    GError **error)
{
	/* find command */
	for (guint i = 0; i < priv->cmd_array->len; i++) {
		FuUtilItem *item = g_ptr_array_index(priv->cmd_array, i);
		if (g_strcmp0(item->name, command) == 0)
			return item->callback(priv, values, error);
	}

	/* not found */
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_FAILED,
			    /* TRANSLATORS: error message */
			    _("Command not found"));
	return FALSE;
}

static gboolean
fwupd_jcat_tool_info(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autofree gchar *str = NULL;

	/* check args */
	if (g_strv_length(values) != 1) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME");
		return FALSE;
	}

	/* import file */
	gfile = g_file_new_for_path(values[0]);
	if (!fwupd_jcat_file_import_file(file,
					 gfile,
					 FWUPD_JCAT_IMPORT_FLAG_NONE,
					 priv->cancellable,
					 error))
		return FALSE;

	/* output to console */
	str = fwupd_jcat_file_to_string(file);
	g_print("%s", str);

	/* success */
	return TRUE;
}

static gboolean
fwupd_jcat_tool_add_alias(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(FwupdJcatItem) item = NULL;

	/* check args */
	if (g_strv_length(values) != 3) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME ID ALIAS_ID");
		return FALSE;
	}

	/* import file */
	gfile = g_file_new_for_path(values[0]);
	if (!fwupd_jcat_file_import_file(file,
					 gfile,
					 FWUPD_JCAT_IMPORT_FLAG_NONE,
					 priv->cancellable,
					 error))
		return FALSE;

	/* add alias */
	item = fwupd_jcat_file_get_item_by_id(file, values[1], error);
	if (item == NULL)
		return FALSE;
	fwupd_jcat_item_add_alias_id(item, values[2]);

	/* export new file */
	return fwupd_jcat_file_export_file(file,
					   gfile,
					   FWUPD_JCAT_EXPORT_FLAG_NONE,
					   priv->cancellable,
					   error);
}

static gboolean
fwupd_jcat_tool_remove_alias(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(FwupdJcatItem) item = NULL;

	/* check args */
	if (g_strv_length(values) != 3) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME ID ALIAS_ID");
		return FALSE;
	}

	/* import file */
	gfile = g_file_new_for_path(values[0]);
	if (!fwupd_jcat_file_import_file(file,
					 gfile,
					 FWUPD_JCAT_IMPORT_FLAG_NONE,
					 priv->cancellable,
					 error))
		return FALSE;

	/* remove alias */
	item = fwupd_jcat_file_get_item_by_id(file, values[1], error);
	if (item == NULL)
		return FALSE;
	fwupd_jcat_item_remove_alias_id(item, values[2]);

	/* export new file */
	return fwupd_jcat_file_export_file(file,
					   gfile,
					   FWUPD_JCAT_EXPORT_FLAG_NONE,
					   priv->cancellable,
					   error);
}

static gchar *
fwupd_jcat_tool_import_convert_id_safe(FwupdJcatToolPrivate *priv, const gchar *filename)
{
	if (priv->basename)
		return g_path_get_basename(filename);
	return g_strdup(filename);
}

static gboolean
fwupd_jcat_tool_import(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatBlob) blob = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(FwupdJcatItem) item = NULL;
	g_autofree gchar *id_safe = NULL;

	/* check args */
	if (g_strv_length(values) != 3) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME DATA DETACHED_KEY");
		return FALSE;
	}

	/* import existing file */
	gfile = g_file_new_for_path(values[0]);
	if (g_file_query_exists(gfile, priv->cancellable)) {
		if (!fwupd_jcat_file_import_file(file,
						 gfile,
						 FWUPD_JCAT_IMPORT_FLAG_NONE,
						 priv->cancellable,
						 error))
			return FALSE;
	}

	/* load source */
	data_sig = fu_bytes_get_contents(values[2], error);
	if (data_sig == NULL)
		return FALSE;

	/* guess format */
	if (g_str_has_suffix(values[2], ".asc")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_GPG,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".btmanifest")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_BT_MANIFEST,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".btcheckpoint")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_BT_CHECKPOINT,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".btinclusionproof")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_BT_INCLUSION_PROOF,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".btverifier")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_BT_VERIFIER,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".btlogindex")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_BT_LOGINDEX,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".p7b") || g_str_has_suffix(values[2], ".p7c") ||
		   g_str_has_suffix(values[2], ".pem")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_PKCS7,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".der")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_PKCS7,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_NONE);
	} else if (g_str_has_suffix(values[2], ".ed25519")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_ED25519,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_NONE);
	} else if (g_str_has_suffix(values[2], ".sha256") ||
		   g_str_has_suffix(values[2], ".SHA256")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_SHA256,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else if (g_str_has_suffix(values[2], ".sha512") ||
		   g_str_has_suffix(values[2], ".SHA512")) {
		blob = fwupd_jcat_blob_new_full(FWUPD_JCAT_BLOB_KIND_SHA512,
						data_sig,
						FWUPD_JCAT_BLOB_FLAG_IS_UTF8);
	} else {
		g_autoptr(GString) tmp = g_string_new(NULL);
		for (guint i = 1; i < FWUPD_JCAT_BLOB_KIND_LAST; i++)
			g_string_append_printf(tmp, "%s,", fwupd_jcat_blob_kind_to_filename_ext(i));
		if (tmp->len > 0)
			g_string_truncate(tmp, tmp->len - 1);
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_FAILED,
			    "Cannot detect blob kind from extension, expected %s",
			    tmp->str);
		return FALSE;
	}

	/* sign the file using the engine */
	id_safe = fwupd_jcat_tool_import_convert_id_safe(priv, values[1]);
	item = fwupd_jcat_file_get_item_by_id(file, id_safe, NULL);
	if (item == NULL) {
		item = fwupd_jcat_item_new(id_safe);
		fwupd_jcat_file_add_item(file, item);
	}

	/* just import existing key */
	if (priv->appstream_id != NULL)
		fwupd_jcat_blob_set_appstream_id(blob, priv->appstream_id);
	fwupd_jcat_item_add_blob(item, blob);

	/* export new file */
	return fwupd_jcat_file_export_file(file,
					   gfile,
					   FWUPD_JCAT_EXPORT_FLAG_NONE,
					   priv->cancellable,
					   error);
}

static gboolean
fwupd_jcat_tool_self_sign(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	FuJcatSignFlags flags = FU_JCAT_VERIFY_FLAG_NONE;
	g_autoptr(GBytes) source = NULL;
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatBlob) blob = NULL;
	g_autoptr(FuJcatEngine) engine = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(FwupdJcatItem) item = NULL;
	g_autofree gchar *id_safe = NULL;

	/* check args */
	if (g_strv_length(values) != 2) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME SOURCE");
		return FALSE;
	}

	/* import existing file */
	gfile = g_file_new_for_path(values[0]);
	if (g_file_query_exists(gfile, priv->cancellable)) {
		if (!fwupd_jcat_file_import_file(file,
						 gfile,
						 FWUPD_JCAT_IMPORT_FLAG_NONE,
						 priv->cancellable,
						 error))
			return FALSE;
	}

	/* create item if required */
	id_safe = fwupd_jcat_tool_import_convert_id_safe(priv, values[1]);
	item = fwupd_jcat_file_get_item_by_id(file, id_safe, NULL);
	if (item == NULL) {
		item = fwupd_jcat_item_new(id_safe);
		fwupd_jcat_file_add_item(file, item);
	}

	/* load source */
	if (priv->target == FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
		source = fu_bytes_get_contents(values[1], error);
		if (source == NULL)
			return FALSE;
	} else {
		g_autoptr(FwupdJcatBlob) blob_target = NULL;
		blob_target = fwupd_jcat_item_get_blob_by_kind(item, priv->target, error);
		if (blob_target == NULL)
			return FALSE;
		source = g_bytes_ref(fwupd_jcat_blob_get_data(blob_target));
	}

	/* sign with this kind */
	if (priv->kind == FWUPD_JCAT_BLOB_KIND_UNKNOWN)
		priv->kind = FWUPD_JCAT_BLOB_KIND_PKCS7;
	if (priv->only_pq)
		flags |= FU_JCAT_VERIFY_FLAG_USE_PQ;
	engine = fu_jcat_context_get_engine(priv->context, priv->kind, error);
	if (engine == NULL)
		return FALSE;
	blob = fu_jcat_engine_self_sign(engine, source, flags, error);
	if (blob == NULL)
		return FALSE;
	if (priv->appstream_id != NULL)
		fwupd_jcat_blob_set_appstream_id(blob, priv->appstream_id);
	if (priv->target != FWUPD_JCAT_BLOB_KIND_UNKNOWN)
		fwupd_jcat_blob_set_target(blob, priv->target);
	fwupd_jcat_item_add_blob(item, blob);

	/* export new file */
	return fwupd_jcat_file_export_file(file,
					   gfile,
					   FWUPD_JCAT_EXPORT_FLAG_NONE,
					   priv->cancellable,
					   error);
}

static gboolean
fwupd_jcat_tool_sign(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GBytes) cert = NULL;
	g_autoptr(GBytes) privkey = NULL;
	g_autoptr(GBytes) source = NULL;
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatBlob) blob = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(FwupdJcatItem) item = NULL;
	g_autoptr(FuJcatEngine) engine = NULL;
	g_autofree gchar *id_safe = NULL;

	/* check args */
	if (g_strv_length(values) != 4) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME "
				    "SOURCE CERT PRIVKEY");
		return FALSE;
	}

	/* import existing file */
	gfile = g_file_new_for_path(values[0]);
	if (g_file_query_exists(gfile, priv->cancellable)) {
		if (!fwupd_jcat_file_import_file(file,
						 gfile,
						 FWUPD_JCAT_IMPORT_FLAG_NONE,
						 priv->cancellable,
						 error))
			return FALSE;
	}

	/* create item if required */
	id_safe = fwupd_jcat_tool_import_convert_id_safe(priv, values[1]);
	item = fwupd_jcat_file_get_item_by_id(file, id_safe, NULL);
	if (item == NULL) {
		item = fwupd_jcat_item_new(id_safe);
		fwupd_jcat_file_add_item(file, item);
	}

	/* load source */
	if (priv->target == FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
		source = fu_bytes_get_contents(values[1], error);
		if (source == NULL)
			return FALSE;
	} else {
		g_autoptr(FwupdJcatBlob) blob_target = NULL;
		blob_target = fwupd_jcat_item_get_blob_by_kind(item, priv->target, error);
		if (blob_target == NULL)
			return FALSE;
		source = g_bytes_ref(fwupd_jcat_blob_get_data(blob_target));
	}

	/* certificate and privatekey */
	cert = fu_bytes_get_contents(values[2], error);
	if (cert == NULL)
		return FALSE;
	privkey = fu_bytes_get_contents(values[3], error);
	if (privkey == NULL)
		return FALSE;

	/* sign with this kind */
	if (priv->kind == FWUPD_JCAT_BLOB_KIND_UNKNOWN)
		priv->kind = FWUPD_JCAT_BLOB_KIND_PKCS7;
	engine = fu_jcat_context_get_engine(priv->context, priv->kind, error);
	if (engine == NULL)
		return FALSE;
	blob = fu_jcat_engine_pubkey_sign(engine,
					  source,
					  cert,
					  privkey,
					  FU_JCAT_VERIFY_FLAG_ADD_TIMESTAMP |
					      FU_JCAT_VERIFY_FLAG_ADD_CERT,
					  error);
	if (blob == NULL)
		return FALSE;
	if (priv->appstream_id != NULL)
		fwupd_jcat_blob_set_appstream_id(blob, priv->appstream_id);
	if (priv->target != FWUPD_JCAT_BLOB_KIND_UNKNOWN)
		fwupd_jcat_blob_set_target(blob, priv->target);
	fwupd_jcat_item_add_blob(item, blob);

	/* export new file */
	return fwupd_jcat_file_export_file(file,
					   gfile,
					   FWUPD_JCAT_EXPORT_FLAG_NONE,
					   priv->cancellable,
					   error);
}

static gboolean
fwupd_jcat_tool_verify_item(FwupdJcatToolPrivate *priv, FwupdJcatItem *item, GError **error)
{
	gboolean ret = TRUE;
	g_autoptr(GBytes) source = NULL;
	g_autoptr(GPtrArray) alias_ids = fwupd_jcat_item_get_alias_ids(item);
	g_autoptr(GPtrArray) blobs = fwupd_jcat_item_get_blobs(item);
	g_autoptr(GPtrArray) fns_possible = g_ptr_array_new_with_free_func(g_free);
	g_autofree gchar *fn_safe = NULL;

	/* load source */
	g_print("%s:\n", fwupd_jcat_item_get_id(item));

	/* find the source */
	g_ptr_array_add(fns_possible,
			g_build_filename(priv->prefix, fwupd_jcat_item_get_id(item), NULL));
	for (guint i = 0; i < alias_ids->len; i++) {
		const gchar *alias_id = g_ptr_array_index(alias_ids, i);
		g_ptr_array_add(fns_possible, g_build_filename(priv->prefix, alias_id, NULL));
	}
	for (guint i = 0; i < fns_possible->len; i++) {
		const gchar *fn = g_ptr_array_index(fns_possible, i);
		if (g_file_test(fn, G_FILE_TEST_EXISTS)) {
			fn_safe = g_strdup(fn);
			break;
		}
	}
	if (fn_safe == NULL) {
		g_autofree gchar *str = NULL;
		g_autofree gchar **strv = g_new0(gchar *, fns_possible->len);
		for (guint i = 0; i < fns_possible->len; i++)
			strv[i] = g_ptr_array_index(fns_possible, i);
		str = g_strjoinv(" or ", strv);
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_FOUND, "Could not find %s", str);
		return FALSE;
	}

	/* load source */
	source = fu_bytes_get_contents(fn_safe, error);
	if (source == NULL)
		return FALSE;

	/* verify blob */
	for (guint j = 0; j < blobs->len; j++) {
		FwupdJcatBlob *blob = g_ptr_array_index(blobs, j);
		FwupdJcatBlobKind target = fwupd_jcat_blob_get_target(blob);
		FuJcatVerifyFlags flags = FU_JCAT_VERIFY_FLAG_NONE;
		const gchar *authority;
		g_autoptr(GError) error_verify = NULL;
		g_autoptr(FuJcatResult) result = NULL;
		g_autoptr(GBytes) blob_source = NULL;
		g_autoptr(GString) kind_str = g_string_new(NULL);

		/* skip */
		if (priv->kind != FWUPD_JCAT_BLOB_KIND_UNKNOWN &&
		    priv->kind != fwupd_jcat_blob_get_kind(blob))
			continue;

		/* get correct source */
		if (target == FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
			blob_source = g_bytes_ref(source);
		} else {
			g_autoptr(FwupdJcatBlob) blob_target = NULL;
			blob_target = fwupd_jcat_item_get_blob_by_kind(item, target, error);
			if (blob_target == NULL)
				return FALSE;
			blob_source = g_bytes_ref(fwupd_jcat_blob_get_data(blob_target));
		}

		g_string_append(kind_str,
				fwupd_jcat_blob_kind_to_string(fwupd_jcat_blob_get_kind(blob)));
		if (fwupd_jcat_blob_get_target(blob) != FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
			g_string_append_printf(
			    kind_str,
			    "-of-%s",
			    fwupd_jcat_blob_kind_to_string(fwupd_jcat_blob_get_target(blob)));
		}
		if (priv->disable_time_checks)
			flags |= FU_JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS;
		if (priv->only_pq)
			flags |= FU_JCAT_VERIFY_FLAG_ONLY_PQ;
		result = fu_jcat_context_verify_blob(priv->context,
						     blob_source,
						     blob,
						     flags,
						     &error_verify);
		if (result == NULL) {
			if (g_error_matches(error_verify, FWUPD_ERROR, FWUPD_ERROR_NOT_FOUND)) {
				g_print("    SKIPPED %s: %s\n",
					kind_str->str,
					error_verify->message);
				continue;
			}
			g_print("    FAILED %s: %s\n", kind_str->str, error_verify->message);
			ret = FALSE;
			continue;
		}
		authority = fwupd_jcat_result_get_authority(result);
		g_print("    PASSED %s: %s\n", kind_str->str, authority != NULL ? authority : "OK");
	}
	if (!ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_DATA, "Validation failed");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fwupd_jcat_tool_export(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();
	g_autoptr(GPtrArray) items = NULL;

	/* check args */
	if (g_strv_length(values) != 1) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME");
		return FALSE;
	}

	/* import existing file */
	gfile = g_file_new_for_path(values[0]);
	if (!fwupd_jcat_file_import_file(file,
					 gfile,
					 FWUPD_JCAT_IMPORT_FLAG_NONE,
					 priv->cancellable,
					 error))
		return FALSE;

	/* verify each file */
	items = fwupd_jcat_file_get_items(file);
	for (guint i = 0; i < items->len; i++) {
		FwupdJcatItem *item = g_ptr_array_index(items, i);
		g_autoptr(GPtrArray) blobs = fwupd_jcat_item_get_blobs(item);
		for (guint j = 0; j < blobs->len; j++) {
			FwupdJcatBlob *blob = g_ptr_array_index(blobs, j);
			g_autofree gchar *fn = NULL;
			g_autoptr(GString) str = NULL;

			/* skip */
			if (priv->kind != FWUPD_JCAT_BLOB_KIND_UNKNOWN &&
			    priv->kind != fwupd_jcat_blob_get_kind(blob))
				continue;

			/* export */
			str = g_string_new(fwupd_jcat_item_get_id(item));
			if (fwupd_jcat_blob_get_appstream_id(blob) != NULL)
				g_string_append_printf(str,
						       "-%s",
						       fwupd_jcat_blob_get_appstream_id(blob));
			g_string_append_printf(
			    str,
			    ".%s",
			    fwupd_jcat_blob_kind_to_filename_ext(fwupd_jcat_blob_get_kind(blob)));
			fn = g_build_filename(priv->prefix, str->str, NULL);
			if (!fu_bytes_set_contents_full(fn,
							fwupd_jcat_blob_get_data(blob),
							0666,
							error))
				return FALSE;
			g_print("Wrote %s\n", fn);
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fwupd_jcat_tool_verify(FwupdJcatToolPrivate *priv, gchar **values, GError **error)
{
	gboolean ret = TRUE;
	g_autoptr(GFile) gfile = NULL;
	g_autoptr(FwupdJcatFile) file = fwupd_jcat_file_new();

	/* check args */
	if (g_strv_length(values) < 1) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_FAILED,
				    "Invalid arguments, expected FILENAME [SOURCE]");
		return FALSE;
	}

	/* import existing file */
	gfile = g_file_new_for_path(values[0]);
	if (!fwupd_jcat_file_import_file(file,
					 gfile,
					 FWUPD_JCAT_IMPORT_FLAG_NONE,
					 priv->cancellable,
					 error))
		return FALSE;

	/* verify each file */
	if (g_strv_length(values) > 1) {
		g_autoptr(FwupdJcatItem) item = NULL;
		g_autofree gchar *id_safe = fwupd_jcat_tool_import_convert_id_safe(priv, values[1]);
		item = fwupd_jcat_file_get_item_by_id(file, id_safe, error);
		if (item == NULL)
			return FALSE;
		if (!fwupd_jcat_tool_verify_item(priv, item, error))
			return FALSE;
	} else {
		g_autoptr(GPtrArray) items = fwupd_jcat_file_get_items(file);
		for (guint i = 0; i < items->len; i++) {
			FwupdJcatItem *item = g_ptr_array_index(items, i);
			g_autoptr(GError) error_local = NULL;
			if (!fwupd_jcat_tool_verify_item(priv, item, &error_local)) {
				g_print("    FAILED: %s\n", error_local->message);
				ret = FALSE;
				continue;
			}
		}
	}
	if (!ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_DATA, "Validation failed");
		return FALSE;
	}

	/* success */
	return TRUE;
}

#ifdef HAVE_GIO_UNIX
static gboolean
fwupd_jcat_tool_sigint_cb(gpointer user_data)
{
	FwupdJcatToolPrivate *priv = (FwupdJcatToolPrivate *)user_data;
	g_debug("Handling SIGINT");
	g_cancellable_cancel(priv->cancellable);
	return FALSE;
}
#endif

int
main(int argc, char *argv[])
{
	gboolean basename = FALSE;
	gboolean ret;
	gboolean verbose = FALSE;
	gboolean version = FALSE;
	g_autofree gchar *appstream_id = NULL;
	g_autofree gchar *cmd_descriptions = NULL;
	g_autofree gchar *keyring_path = NULL;
	g_autofree gchar *kind = NULL;
	g_autofree gchar *target = NULL;
	g_autofree gchar *prefix = NULL;
	g_auto(GStrv) public_key = NULL;
	g_auto(GStrv) public_keys = NULL;
	g_autoptr(FwupdJcatToolPrivate) priv = g_new0(FwupdJcatToolPrivate, 1);
	g_autoptr(GError) error = NULL;
	g_autoptr(GOptionContext) context = NULL;
	const GOptionEntry options[] = {
	    {"version", '\0', 0, G_OPTION_ARG_NONE, &version, _("Print the version number"), NULL},
	    {"verbose",
	     'v',
	     0,
	     G_OPTION_ARG_NONE,
	     &verbose,
	     _("Print verbose debug statements"),
	     NULL},
	    {"basename",
	     'v',
	     0,
	     G_OPTION_ARG_NONE,
	     &basename,
	     _("Only consider the basename for the ID"),
	     NULL},
	    {"disable-time-checks",
	     'v',
	     0,
	     G_OPTION_ARG_NONE,
	     &priv->disable_time_checks,
	     _("Disable time checks when verifying"),
	     NULL},
	    {"only-pq",
	     'v',
	     0,
	     G_OPTION_ARG_NONE,
	     &priv->only_pq,
	     _("Only consider post-quantum signatures"),
	     NULL},
	    {"public-key",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING_ARRAY,
	     &public_key,
	     _("Location of public key used for verification"),
	     NULL},
	    {"public-keys",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING_ARRAY,
	     &public_keys,
	     _("Location of public key directories used for verification"),
	     NULL},
	    {"prefix",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING,
	     &prefix,
	     _("Prefix for import and output files"),
	     NULL},
	    {"kind", '\0', 0, G_OPTION_ARG_STRING, &kind, _("Kind for blob, e.g. `gpg`"), NULL},
	    {"target",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING,
	     &target,
	     _("Target for blob, e.g. `sha256`"),
	     NULL},
	    {"appstream-id",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING,
	     &appstream_id,
	     _("Appstream ID for blob, e.g. `com.bbc`"),
	     NULL},
	    {"keyring",
	     '\0',
	     0,
	     G_OPTION_ARG_STRING,
	     &keyring_path,
	     _("Keyring location, e.g. `/var/lib/fwupd`"),
	     NULL},
	    {NULL}};

#ifdef _WIN32
	/* workaround Windows setting the codepage to 1252 */
	g_setenv("LANG", "C.UTF-8", FALSE);
#endif

	setlocale(LC_ALL, "");

	bindtextdomain(GETTEXT_PACKAGE, FWUPD_JCAT_LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
	textdomain(GETTEXT_PACKAGE);

	/* add commands */
	priv->cmd_array = g_ptr_array_new_with_free_func((GDestroyNotify)fwupd_jcat_tool_item_free);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "info",
			    "FILENAME",
			    /* TRANSLATORS: command description */
			    _("Show information about a file"),
			    fwupd_jcat_tool_info);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "self-sign",
			    "FILENAME SOURCE",
			    /* TRANSLATORS: command description */
			    _("Add a self-signed signature to a file"),
			    fwupd_jcat_tool_self_sign);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "sign",
			    "FILENAME SOURCE CERT PRIVKEY",
			    /* TRANSLATORS: command description */
			    _("Add a signature to a file"),
			    fwupd_jcat_tool_sign);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "import",
			    "FILENAME DATA DETACHED_KEY",
			    /* TRANSLATORS: command description */
			    _("Import an existing signature to a file"),
			    fwupd_jcat_tool_import);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "export",
			    "FILENAME",
			    /* TRANSLATORS: command description */
			    _("Exports all embedded signatures to files"),
			    fwupd_jcat_tool_export);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "verify",
			    "FILENAME [SOURCE]",
			    /* TRANSLATORS: command description */
			    _("Verify a signature from a file"),
			    fwupd_jcat_tool_verify);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "add-alias",
			    "FILENAME ID ALIAS_ID",
			    /* TRANSLATORS: command description */
			    _("Add an alias for a specific item"),
			    fwupd_jcat_tool_add_alias);
	fwupd_jcat_tool_add(priv->cmd_array,
			    "remove-alias",
			    "FILENAME ID ALIAS_ID",
			    /* TRANSLATORS: command description */
			    _("Remove an alias for a specific item"),
			    fwupd_jcat_tool_remove_alias);

	/* do stuff on ctrl+c */
	priv->cancellable = g_cancellable_new();
#ifdef HAVE_GIO_UNIX
	g_unix_signal_add_full(G_PRIORITY_DEFAULT, SIGINT, fwupd_jcat_tool_sigint_cb, priv, NULL);
#endif

	/* sort by command name */
	g_ptr_array_sort(priv->cmd_array, (GCompareFunc)fwupd_jcat_tool_sort_command_name_cb);

	/* get a list of the commands */
	context = g_option_context_new(NULL);
	cmd_descriptions = fwupd_jcat_tool_get_descriptions(priv->cmd_array);
	g_option_context_set_summary(context, cmd_descriptions);

	/* TRANSLATORS: FWUPD_JCAT stands for device firmware update */
	g_set_application_name(_("JSON Catalog Utility"));
	g_option_context_add_main_entries(context, options, NULL);
	ret = g_option_context_parse(context, &argc, &argv, &error);
	if (!ret) {
		/* TRANSLATORS: the user didn't read the man page */
		g_print("%s: %s\n", _("Failed to parse arguments"), error->message);
		return EXIT_FAILURE;
	}

	/* create context */
	priv->basename = basename;
	priv->appstream_id = g_strdup(appstream_id);
	priv->prefix = g_strdup(prefix != NULL ? prefix : ".");
	priv->context = fu_jcat_context_new();
	if (public_key != NULL) {
		for (guint i = 0; public_key[i] != NULL; i++)
			fu_jcat_context_add_public_key(priv->context, public_key[i]);
	}
	if (public_keys != NULL) {
		for (guint i = 0; public_keys[i] != NULL; i++)
			fu_jcat_context_add_public_keys(priv->context, public_keys[i]);
	}
	if (keyring_path != NULL)
		fu_jcat_context_set_keyring_path(priv->context, keyring_path);
	if (kind != NULL) {
		priv->kind = fwupd_jcat_blob_kind_from_string(kind);
		if (priv->kind == FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
			g_autoptr(GString) tmp = g_string_new(NULL);
			for (guint i = 1; i < FWUPD_JCAT_BLOB_KIND_LAST; i++)
				g_string_append_printf(tmp,
						       "%s,",
						       fwupd_jcat_blob_kind_to_string(i));
			if (tmp->len > 0)
				g_string_truncate(tmp, tmp->len - 1);
			g_printerr("Failed to parse '%s', expected %s", kind, tmp->str);
			return EXIT_FAILURE;
		}
	}
	if (target != NULL) {
		priv->target = fwupd_jcat_blob_kind_from_string(target);
		if (priv->target == FWUPD_JCAT_BLOB_KIND_UNKNOWN) {
			g_printerr("Failed to parse target '%s', expected checksum", kind);
			return EXIT_FAILURE;
		}
	}

	/* set verbose? */
	if (verbose)
		g_setenv("G_MESSAGES_DEBUG", "all", FALSE);

	/* version */
	if (version) {
		g_print("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
		return EXIT_SUCCESS;
	}

	/* run the specified command */
	ret = fwupd_jcat_tool_run(priv, argv[1], (gchar **)&argv[2], &error);
	if (!ret) {
		if (g_error_matches(error, FWUPD_ERROR, FWUPD_ERROR_FAILED)) {
			g_autofree gchar *tmp = NULL;
			tmp = g_option_context_get_help(context, TRUE, NULL);
			g_print("%s\n\n%s", error->message, tmp);
		} else {
			g_print("%s\n", error->message);
		}
		return EXIT_FAILURE;
	}

	/* success/ */
	return EXIT_SUCCESS;
}
