/*
 * Copyright (C) 2017-2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gpgme.h>

#include "jcat-gpg-engine.h"
#include "jcat-engine-private.h"

struct _JcatGpgEngine
{
	JcatEngine		 parent_instance;
	gpgme_ctx_t		 ctx;
};

G_DEFINE_TYPE (JcatGpgEngine, jcat_gpg_engine, JCAT_TYPE_ENGINE)

G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gpgme_data_t, gpgme_data_release, NULL)

static gboolean
jcat_gpg_engine_add_public_key (JcatEngine *engine,
			        const gchar *filename,
			        GError **error)
{
	JcatGpgEngine *self = JCAT_GPG_ENGINE (engine);
	gpgme_error_t rc;
	gpgme_import_result_t result;
	gpgme_import_status_t s;
	g_auto(gpgme_data_t) data = NULL;
	g_autofree gchar *basename = g_path_get_basename (filename);

	/* not us */
	if (!g_str_has_prefix (basename, "GPG-KEY-")) {
		g_debug ("ignoring %s as not GPG public key", basename);
		return TRUE;
	}

	/* import public key */
	g_debug ("Adding GnuPG public key %s", filename);
	rc = gpgme_data_new_from_file (&data, filename, 1);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to load %s: %s",
			     filename, gpgme_strerror (rc));
		return FALSE;
	}
	rc = gpgme_op_import (self->ctx, data);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to import %s: %s",
			     filename, gpgme_strerror (rc));
		return FALSE;
	}

	/* print what keys were imported */
	result = gpgme_op_import_result (self->ctx);
	for (s = result->imports; s != NULL; s = s->next) {
		g_debug ("importing key %s [%u] %s",
			 s->fpr, s->status, gpgme_strerror (s->result));
	}

	/* make sure keys were really imported */
	if (result->imported == 0 && result->unchanged == 0) {
		g_debug("imported: %d, unchanged: %d, not_imported: %d",
			result->imported,
			result->unchanged,
			result->not_imported);
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "key import failed %s",
			     filename);
		return FALSE;
	}
	return TRUE;
}

static gboolean
jcat_gpg_engine_setup (JcatEngine *engine, GError **error)
{
	JcatGpgEngine *self = JCAT_GPG_ENGINE (engine);
	gpgme_error_t rc;
	g_autofree gchar *gpg_home = NULL;

	if (self->ctx != NULL)
		return TRUE;

	/* startup gpgme */
	rc = gpg_err_init ();
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to init: %s",
			     gpgme_strerror (rc));
		return FALSE;
	}

	/* create a new GPG context */
	g_debug ("using gpgme v%s", gpgme_check_version (NULL));
	rc = gpgme_new (&self->ctx);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to create context: %s",
			     gpgme_strerror (rc));
		return FALSE;
	}

	/* set the protocol */
	rc = gpgme_set_protocol (self->ctx, GPGME_PROTOCOL_OpenPGP);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to set protocol: %s",
			     gpgme_strerror (rc));
		return FALSE;
	}

	/* set a custom home directory */
	gpg_home = g_build_filename (jcat_engine_get_keyring_path (engine), "gnupg", NULL);
	if (g_mkdir_with_parents (gpg_home, 0700) < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to create %s",
			     gpg_home);
		return FALSE;
	}
	g_debug ("Using engine at %s", gpg_home);
	rc = gpgme_ctx_set_engine_info (self->ctx,
					GPGME_PROTOCOL_OpenPGP,
					NULL,
					gpg_home);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to set protocol: %s",
			     gpgme_strerror (rc));
		return FALSE;
	}

	/* enable armor mode */
	gpgme_set_armor (self->ctx, TRUE);
	return TRUE;
}

static gboolean
jcat_gpg_engine_check_signature (gpgme_signature_t signature, GError **error)
{
	gboolean ret = FALSE;

	/* look at the signature status */
	switch (gpgme_err_code (signature->status)) {
	case GPG_ERR_NO_ERROR:
		ret = TRUE;
		break;
	case GPG_ERR_SIG_EXPIRED:
	case GPG_ERR_KEY_EXPIRED:
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "valid signature '%s' has expired",
			     signature->fpr);
		break;
	case GPG_ERR_CERT_REVOKED:
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "valid signature '%s' has been revoked",
			     signature->fpr);
		break;
	case GPG_ERR_BAD_SIGNATURE:
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "'%s' is not a valid signature",
			     signature->fpr);
		break;
	case GPG_ERR_NO_PUBKEY:
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "Could not check signature '%s' as no public key",
			     signature->fpr);
		break;
	default:
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_INVALID_DATA,
			     "gpgme failed to verify signature '%s'",
			     signature->fpr);
		break;
	}
	return ret;
}

static JcatResult *
jcat_gpg_engine_pubkey_verify (JcatEngine *engine,
			     GBytes *blob,
			     GBytes *blob_signature,
			     JcatVerifyFlags flags,
			     GError **error)
{
	JcatGpgEngine *self = JCAT_GPG_ENGINE (engine);
	gpgme_error_t rc;
	gpgme_signature_t s;
	gpgme_verify_result_t result;
	gint64 timestamp_newest = 0;
	g_auto(gpgme_data_t) data = NULL;
	g_auto(gpgme_data_t) sig = NULL;
	g_autoptr(GString) authority_newest = g_string_new (NULL);

	/* load file data */
	rc = gpgme_data_new_from_mem (&data,
				      g_bytes_get_data (blob, NULL),
				      g_bytes_get_size (blob), 0);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to load data: %s",
			     gpgme_strerror (rc));
		return NULL;
	}
	rc = gpgme_data_new_from_mem (&sig,
				      g_bytes_get_data (blob_signature, NULL),
				      g_bytes_get_size (blob_signature), 0);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to load signature: %s",
			      gpgme_strerror (rc));
		return NULL;
	}

	/* verify */
	rc = gpgme_op_verify (self->ctx, sig, data, NULL);
	if (rc != GPG_ERR_NO_ERROR) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to verify data: %s",
			     gpgme_strerror (rc));
		return NULL;
	}


	/* verify the result */
	result = gpgme_op_verify_result (self->ctx);
	if (result == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "no result record from libgpgme");
		return NULL;
	}
	if (result->signatures == NULL) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "no signatures from libgpgme");
		return NULL;
	}

	/* look at each signature */
	for (s = result->signatures; s != NULL ; s = s->next ) {
		g_debug ("returned signature fingerprint %s", s->fpr);
		if (!jcat_gpg_engine_check_signature (s, error))
			return NULL;

		/* save details about the key for the result */
		if ((gint64) s->timestamp > timestamp_newest) {
			timestamp_newest = (gint64) s->timestamp;
			g_string_assign (authority_newest, s->fpr);
		}
	}
	return JCAT_RESULT (g_object_new (JCAT_TYPE_RESULT,
					  "engine", engine,
					  "timestamp", timestamp_newest,
					  "authority", authority_newest->str,
					  NULL));
}

static void
jcat_gpg_engine_finalize (GObject *object)
{
	JcatGpgEngine *self = JCAT_GPG_ENGINE (object);
	if (self->ctx != NULL)
		gpgme_release (self->ctx);
	G_OBJECT_CLASS (jcat_gpg_engine_parent_class)->finalize (object);
}

static void
jcat_gpg_engine_class_init (JcatGpgEngineClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	JcatEngineClass *klass_app = JCAT_ENGINE_CLASS (klass);
	klass_app->setup = jcat_gpg_engine_setup;
	klass_app->add_public_key = jcat_gpg_engine_add_public_key;
	klass_app->pubkey_verify = jcat_gpg_engine_pubkey_verify;
	object_class->finalize = jcat_gpg_engine_finalize;
}

static void
jcat_gpg_engine_init (JcatGpgEngine *self)
{
}

JcatEngine *
jcat_gpg_engine_new (JcatContext *context)
{
	g_return_val_if_fail (JCAT_IS_CONTEXT (context), NULL);
	return JCAT_ENGINE (g_object_new (JCAT_TYPE_GPG_ENGINE,
					  "context", context,
					  "kind", JCAT_BLOB_KIND_GPG,
					  "method", JCAT_BLOB_METHOD_SIGNATURE,
					  NULL));
}
