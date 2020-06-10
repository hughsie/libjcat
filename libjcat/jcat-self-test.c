/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "jcat-blob-private.h"
#include "jcat-common-private.h"
#include "jcat-context.h"
#include "jcat-engine-private.h"
#include "jcat-file.h"
#include "jcat-item-private.h"
#include "jcat-result-private.h"

static void
jcat_blob_func (void)
{
	g_autofree gchar *str = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	const gchar *str_perfect =
		"JcatBlob:\n"
		"  Kind:                  gpg\n"
		"  Flags:                 is-utf8\n"
		"  AppstreamId:           org.fwupd\n"
		"  Timestamp:             1970-01-01T03:25:45Z\n"
		"  Size:                  0x5\n"
		"  Data:                  BEGIN\n";

	/* enums */
	for (guint i = JCAT_BLOB_KIND_UNKNOWN + 1; i < JCAT_BLOB_KIND_LAST; i++) {
		const gchar *tmp = jcat_blob_kind_to_string (i);
		g_assert_nonnull (tmp);
		g_assert_cmpint (jcat_blob_kind_from_string (tmp), ==, i);
	}
	for (guint i = JCAT_BLOB_KIND_UNKNOWN + 1; i < JCAT_BLOB_KIND_LAST; i++) {
		const gchar *tmp = jcat_blob_kind_to_filename_ext (i);
		g_assert_nonnull (tmp);
	}

	/* sanity check */
	blob = jcat_blob_new_utf8 (JCAT_BLOB_KIND_GPG, "BEGIN");
	g_assert_cmpint (jcat_blob_get_kind (blob), ==, JCAT_BLOB_KIND_GPG);
	g_assert_nonnull (jcat_blob_get_data (blob));
	jcat_blob_set_appstream_id (blob, "org.fwupd");
	g_assert_cmpstr (jcat_blob_get_appstream_id (blob), ==, "org.fwupd");
	jcat_blob_set_timestamp (blob, 12345);
	g_assert_cmpint (jcat_blob_get_timestamp (blob), ==, 12345);

	/* to string */
	str = jcat_blob_to_string (blob);
	g_print ("%s", str);
	g_assert_cmpstr (str, ==, str_perfect);
}

static void
jcat_item_func (void)
{
	g_autofree gchar *str = NULL;
	g_autoptr(JcatItem) item = NULL;
	const gchar *str_perfect =
		"JcatItem:\n"
		"  ID:                    filename.bin\n"
		"  AliasId:               foo.bin\n";

	/* sanity check */
	item = jcat_item_new ("filename.bin");
	jcat_item_add_alias_id (item, "foo.bin");
	jcat_item_add_alias_id (item, "bar.bin");
	jcat_item_remove_alias_id (item, "bar.bin");
	g_assert_cmpstr (jcat_item_get_id (item), ==, "filename.bin");

	/* to string */
	str = jcat_item_to_string (item);
	g_print ("%s", str);
	g_assert_cmpstr (str, ==, str_perfect);
}

static void
jcat_file_func (void)
{
	gboolean ret;
	g_autofree gchar *json1 = NULL;
	g_autofree gchar *json2 = NULL;
	g_autoptr(GBytes) data = g_bytes_new ("hello world", 12);
	g_autoptr(GError) error = NULL;
	g_autoptr(GFile) gfile = g_file_new_for_path ("/tmp/firmware.jcat");
	g_autoptr(GPtrArray) blobs0 = NULL;
	g_autoptr(GPtrArray) blobs1 = NULL;
	g_autoptr(GPtrArray) blobs2 = NULL;
	g_autoptr(GPtrArray) blobs3 = NULL;
	g_autoptr(GPtrArray) items0 = NULL;
	g_autoptr(GPtrArray) items1 = NULL;
	g_autoptr(JcatBlob) blob1 = jcat_blob_new_utf8 (JCAT_BLOB_KIND_GPG, "BEGIN");
	g_autoptr(JcatBlob) blob2 = jcat_blob_new (JCAT_BLOB_KIND_SHA256, data);
	g_autoptr(JcatFile) file2 = jcat_file_new ();
	g_autoptr(JcatFile) file = jcat_file_new ();
	g_autoptr(JcatItem) item1 = NULL;
	g_autoptr(JcatItem) item2 = NULL;
	g_autoptr(JcatItem) item3 = NULL;
	g_autoptr(JcatItem) item = jcat_item_new ("firmware.bin");
	const gchar *json_perfect =
		"{\n"
		"  \"JcatVersionMajor\" : 0,\n"
		"  \"JcatVersionMinor\" : 1,\n"
		"  \"Items\" : [\n"
		"    {\n"
		"      \"Id\" : \"firmware.bin\",\n"
		"      \"AliasIds\" : [\n"
		"        \"foo.bin\"\n"
		"      ],\n"
		"      \"Blobs\" : [\n"
		"        {\n"
		"          \"Kind\" : 2,\n"
		"          \"Flags\" : 1,\n"
		"          \"AppstreamId\" : \"org.fwupd\",\n"
		"          \"Data\" : \"BEGIN\"\n"
		"        },\n"
		"        {\n"
		"          \"Kind\" : 1,\n"
		"          \"Flags\" : 0,\n"
		"          \"Data\" : \"aGVsbG8gd29ybGQA\"\n"
		"        }\n"
		"      ]\n"
		"    }\n"
		"  ]\n"
		"}";

	/* check blob */
	g_assert (jcat_blob_get_data (blob2) == data);
	jcat_blob_set_appstream_id (blob1, "org.fwupd");
	g_assert_cmpstr (jcat_blob_get_appstream_id (blob1), ==, "org.fwupd");
	jcat_blob_set_timestamp (blob1, 0);
	g_assert_cmpint (jcat_blob_get_timestamp (blob1), ==, 0);
	jcat_blob_set_timestamp (blob2, 0);
	g_assert_cmpint (jcat_blob_get_timestamp (blob2), ==, 0);

	/* get default item */
	item1 = jcat_file_get_item_default (file, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null (item1);
	g_clear_error (&error);

	/* check item */
	g_assert_cmpstr (jcat_item_get_id (item), ==, "firmware.bin");
	blobs0 = jcat_item_get_blobs (item);
	g_assert_cmpint (blobs0->len, ==, 0);
	jcat_item_add_blob (item, blob1);
	jcat_item_add_blob (item, blob2);
	jcat_item_add_blob (item, blob2);
	jcat_item_add_alias_id (item, "foo.bin");
	blobs1 = jcat_item_get_blobs (item);
	g_assert_cmpint (blobs1->len, ==, 2);
	blobs2 = jcat_item_get_blobs_by_kind (item, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint (blobs2->len, ==, 1);
	blobs3 = jcat_item_get_blobs_by_kind (item, JCAT_BLOB_KIND_PKCS7);
	g_assert_cmpint (blobs3->len, ==, 0);

	/* check file */
	g_assert_cmpint (jcat_file_get_version_major (file), ==, 0);
	g_assert_cmpint (jcat_file_get_version_minor (file), ==, 1);
	items0 = jcat_file_get_items (file);
	g_assert_cmpint (items0->len, ==, 0);
	jcat_file_add_item (file, item);
	items1 = jcat_file_get_items (file);
	g_assert_cmpint (items1->len, ==, 1);
	item1 = jcat_file_get_item_by_id (file, "firmware.bin", &error);
	g_assert_no_error (error);
	g_assert_nonnull (item1);
	g_assert (item == item1);
	item2 = jcat_file_get_item_by_id (file, "dave.bin", &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null (item2);
	g_clear_error (&error);

	/* get default item */
	item3 = jcat_file_get_item_default (file, &error);
	g_assert_no_error (error);
	g_assert_nonnull (item3);

	/* export as string */
	json1 = jcat_file_export_json (file, JCAT_EXPORT_FLAG_NONE, &error);
	g_print ("%s\n", json1);
	g_assert_cmpstr (json1, ==, json_perfect);

	/* export as compressed file */
	ret = jcat_file_export_file (file, gfile, JCAT_EXPORT_FLAG_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ret);

	/* load compressed file */
	ret = jcat_file_import_file (file2, gfile, JCAT_IMPORT_FLAG_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	json2 = jcat_file_export_json (file2, JCAT_EXPORT_FLAG_NO_TIMESTAMP, &error);
	g_print ("%s\n", json2);
	g_assert_cmpstr (json2, ==, json1);
}

static void
jcat_sha1_engine_func (void)
{
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autofree gchar *sig = NULL;
	g_autoptr(GBytes) blob_sig1 = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob_sig2 = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *sig_actual = "7c0ae84b191822bcadbdcbe2f74a011695d783c7";

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_SHA1, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);
	g_assert_cmpint (jcat_engine_get_kind (engine), ==, JCAT_BLOB_KIND_SHA1);
	g_assert_cmpint (jcat_engine_get_method (engine), ==, JCAT_BLOB_METHOD_CHECKSUM);

	/* verify checksum */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	blob_sig1 = g_bytes_new_static (sig_actual, strlen (sig_actual));
	result_pass = jcat_engine_self_verify (engine, data_fwbin, blob_sig1,
					       JCAT_VERIFY_FLAG_NONE,
					       &error);
	g_assert_no_error (error);
	g_assert_nonnull (result_pass);
	g_assert_cmpint (jcat_result_get_timestamp (result_pass), ==, 0);
	g_assert_cmpstr (jcat_result_get_authority (result_pass), ==, NULL);

	/* verify will fail */
	fn_fail = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes (fn_fail, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fail);
	result_fail = jcat_engine_self_verify (engine, data_fail, blob_sig1,
					       JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null (result_fail);
	g_clear_error (&error);

	/* verify signing */
	blob_sig2 = jcat_engine_self_sign (engine, data_fwbin, JCAT_SIGN_FLAG_NONE, &error);
	g_assert_no_error (error);
	g_assert_nonnull (blob_sig2);
	sig = jcat_blob_get_data_as_string (blob_sig2);
	g_assert_cmpstr (sig, ==, sig_actual);
}

static void
jcat_sha256_engine_func (void)
{
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autofree gchar *sig = NULL;
	g_autoptr(GBytes) blob_sig1 = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob_sig2 = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *sig_actual = "a196504d09871da4f7d83b874b500f8ee6e0619ab799f074814b316d88f96f7f";

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);
	g_assert_cmpint (jcat_engine_get_kind (engine), ==, JCAT_BLOB_KIND_SHA256);
	g_assert_cmpint (jcat_engine_get_method (engine), ==, JCAT_BLOB_METHOD_CHECKSUM);

	/* verify checksum */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	blob_sig1 = g_bytes_new_static (sig_actual, strlen (sig_actual));
	result_pass = jcat_engine_self_verify (engine, data_fwbin, blob_sig1,
					       JCAT_VERIFY_FLAG_NONE,
					       &error);
	g_assert_no_error (error);
	g_assert_nonnull (result_pass);
	g_assert_cmpint (jcat_result_get_timestamp (result_pass), ==, 0);
	g_assert_cmpstr (jcat_result_get_authority (result_pass), ==, NULL);

	/* verify will fail */
	fn_fail = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes (fn_fail, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fail);
	result_fail = jcat_engine_self_verify (engine, data_fail, blob_sig1,
					       JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null (result_fail);
	g_clear_error (&error);

	/* verify signing */
	blob_sig2 = jcat_engine_self_sign (engine, data_fwbin, JCAT_SIGN_FLAG_NONE, &error);
	g_assert_no_error (error);
	g_assert_nonnull (blob_sig2);
	sig = jcat_blob_get_data_as_string (blob_sig2);
	g_assert_cmpstr (sig, ==, sig_actual);
}

static void
jcat_gpg_engine_func (void)
{
#ifdef ENABLE_GPG
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autofree gchar *str = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *str_perfect =
		"JcatGpgEngine:\n"
		"  Kind:                  gpg\n"
		"  VerifyKind:            signature\n";
	const gchar *sig_actual =
	"-----BEGIN PGP SIGNATURE-----\n"
	"Version: GnuPG v1\n\n"
	"iQEcBAABCAAGBQJVt0B4AAoJEEim2A5FOLrCFb8IAK+QTLY34Wu8xZ8nl6p3JdMu"
	"HOaifXAmX7291UrsFRwdabU2m65pqxQLwcoFrqGv738KuaKtu4oIwo9LIrmmTbEh"
	"IID8uszxBt0bMdcIHrvwd+ADx+MqL4hR3guXEE3YOBTLvv2RF1UBcJPInNf/7Ui1"
	"3lW1c3trL8RAJyx1B5RdKqAMlyfwiuvKM5oT4SN4uRSbQf+9mt78ZSWfJVZZH/RR"
	"H9q7PzR5GdmbsRPM0DgC27Trvqjo3MzoVtoLjIyEb/aWqyulUbnJUNKPYTnZgkzM"
	"v2yVofWKIM3e3wX5+MOtf6EV58mWa2cHJQ4MCYmpKxbIvAIZagZ4c9A8BA6tQWg="
	"=fkit\n"
	"-----END PGP SIGNATURE-----\n";

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);
	g_assert_cmpint (jcat_engine_get_kind (engine), ==, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint (jcat_engine_get_method (engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* to string */
	str = jcat_engine_to_string (engine);
	g_print ("%s", str);
	g_assert_cmpstr (str, ==, str_perfect);

	/* verify with GnuPG */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	data_sig = g_bytes_new_static (sig_actual, strlen (sig_actual));
	result_pass = jcat_engine_pubkey_verify (engine, data_fwbin, data_sig,
					  JCAT_VERIFY_FLAG_NONE,
					  &error);
	g_assert_no_error (error);
	g_assert_nonnull (result_pass);
	g_assert_cmpint (jcat_result_get_timestamp (result_pass), == , 1438072952);
	g_assert_cmpstr (jcat_result_get_authority (result_pass), == ,
			 "3FC6B804410ED0840D8F2F9748A6D80E4538BAC2");

	/* verify will fail with GnuPG */
	fn_fail = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes (fn_fail, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fail);
	result_fail = jcat_engine_pubkey_verify (engine, data_fail, data_sig,
						 JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null (result_fail);
	g_clear_error (&error);
#else
	g_test_skip ("no GnuPG support enabled");
#endif
}

static void
jcat_gpg_engine_msg_func (void)
{
#ifdef ENABLE_GPG
	g_autofree gchar *fn = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result = NULL;
	const gchar *sig =
	"-----BEGIN PGP MESSAGE-----\n"
	"owGbwMvMwMEovmZX76/pfOKMp0WSGOLOX3/ikZqTk6+jUJ5flJOiyNXJaMzCwMjB\n"
	"ICumyCJmt5VRUil28/1+z1cwbaxMID0MXJwCMJG4RxwMLUYXDkUad34I3vrT8+X2\n"
	"m+ZyHyMWnTiQYaQb/eLJGqbiAJc5Jr4a/PPqHNi7auwzGsKsljebabjtnJRzpDr0\n"
	"YvwrnmmWLJUnTzjM3MH5Kn+RzqXkywsYdk9yD2OUdLy736CiemFMdcuF02lOZvPU\n"
	"HaTKl76wW62QH8Lr8yGMQ1Xgc6nC2ZwUhvctky7NOZtc1T477uBTL81p31ZmaIUJ\n"
	"paS8uWZl8UzX5sFsqQi37G1TbDc8Cm+oU/yRkFj2pLBzw367ncsa4n7EqEWu1yrN\n"
	"yD39LUeErePdqfKCG+xhL6WkWt5ZJ/6//XnjouXhl5Z4tWspT49MtNp5d3aDQ43c\n"
	"mnbresn6A7KMZgdOiwIA\n"
	"=a9ui\n"
	"-----END PGP MESSAGE-----\n";

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);
	g_assert_cmpint (jcat_engine_get_kind (engine), ==, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint (jcat_engine_get_method (engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* verify with GnuPG, which should fail as the signature is not a
	 * detached signature at all, but gnupg stabs us in the back by returning
	 * success from gpgme_op_verify() with an empty list of signatures */
	fn = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data = jcat_get_contents_bytes (fn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data);
	data_sig = g_bytes_new_static (sig, strlen (sig));
	result = jcat_engine_pubkey_verify (engine, data, data_sig,
					    JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_assert_null (result);
#else
	g_test_skip ("no GnuPG support enabled");
#endif
}

static void
jcat_pkcs7_engine_func (void)
{
#ifdef ENABLE_PKCS7
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *fn_sig = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autofree gchar *sig_fn2 = NULL;
	g_autoptr(GBytes) blob_sig2 = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);
	g_assert_cmpint (jcat_engine_get_kind (engine), ==, JCAT_BLOB_KIND_PKCS7);
	g_assert_cmpint (jcat_engine_get_method (engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* verify with a signature from the old LVFS */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	fn_sig = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes (fn_sig, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_sig);
	result_pass = jcat_engine_pubkey_verify (engine, data_fwbin, data_sig,
					  JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS,
					  &error);
	g_assert_no_error (error);
	g_assert_nonnull (result_pass);
	g_assert_cmpint (jcat_result_get_timestamp (result_pass), >= , 1502871248);
	g_assert_cmpstr (jcat_result_get_authority (result_pass), == , "O=Linux Vendor Firmware Project,CN=LVFS CA");

	/* verify will fail with a self-signed signature */
	sig_fn2 = g_test_build_filename (G_TEST_BUILT, "colorhug", "firmware.bin.p7c", NULL);
	blob_sig2 = jcat_get_contents_bytes (sig_fn2, &error);
	g_assert_no_error (error);
	g_assert_nonnull (blob_sig2);
	result_fail = jcat_engine_pubkey_verify (engine, data_fwbin, blob_sig2,
						 JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null (result_fail);
	g_clear_error (&error);

	/* verify will fail with valid signature and different data */
	fn_fail = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes (fn_fail, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fail);
	result_fail = jcat_engine_pubkey_verify (engine, data_fail, data_sig,
						 JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null (result_fail);
	g_clear_error (&error);
#else
	g_test_skip ("no GnuTLS support enabled");
#endif
}

static void
jcat_pkcs7_engine_self_signed_func (void)
{
#ifdef ENABLE_PKCS7
	static const char payload_str[] = "Hello, world!";
	g_autofree gchar *str = NULL;
	g_autoptr(JcatBlob) signature = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatEngine) engine2 = NULL;
	g_autoptr(JcatResult) result = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GError) error = NULL;
	const gchar *str_perfect =
		"JcatResult:\n"
		"  Timestamp:             1970-01-01T03:25:45Z\n"
		"  JcatPkcs7Engine:\n"
		"    Kind:                pkcs7\n"
		"    VerifyKind:          signature\n";

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp");

	/* get engine */
	engine = jcat_context_get_engine (context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine);

	payload = g_bytes_new_static (payload_str, sizeof (payload_str));
	g_assert_nonnull (payload);
	signature = jcat_engine_self_sign (engine, payload, JCAT_SIGN_FLAG_ADD_TIMESTAMP, &error);
	g_assert_no_error (error);
	g_assert_nonnull (signature);
	result = jcat_engine_self_verify (engine, payload, jcat_blob_get_data (signature),
					  JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_no_error (error);
	g_assert_nonnull (result);

	/* verify engine set */
	engine2 = jcat_result_get_engine (result);
	g_assert (engine == engine2);

	/* to string */
	g_object_set (result, "timestamp", (gint64) 12345, NULL);
	str = jcat_result_to_string (result);
	g_print ("%s", str);
	g_assert_cmpstr (str, ==, str_perfect);
#else
	g_test_skip ("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_blob_func (void)
{
#ifdef ENABLE_PKCS7
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *fn_sig = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(JcatResult) result = NULL;

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine (context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine (context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine2);
#endif
	engine3 = jcat_context_get_engine (context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine3);
	engine4 = jcat_context_get_engine (context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null (engine4);
	g_clear_error (&error);

	/* verify blob */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	fn_sig = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes (fn_sig, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_sig);
	blob = jcat_blob_new (JCAT_BLOB_KIND_PKCS7, data_sig);
	result = jcat_context_verify_blob (context, data_fwbin, blob,
					   JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS,
					   &error);
	g_assert_no_error (error);
	g_assert_nonnull (result);
	g_assert_cmpint (jcat_result_get_timestamp (result), >= , 1502871248);
	g_assert_cmpstr (jcat_result_get_authority (result), == , "O=Linux Vendor Firmware Project,CN=LVFS CA");
#else
	g_test_skip ("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_item_sign_func (void)
{
#ifdef ENABLE_PKCS7
	JcatResult *result;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *fn_sig = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	g_autoptr(JcatItem) item = jcat_item_new ("filename.bin");
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(GPtrArray) results_fail = NULL;
	g_autoptr(GPtrArray) results_pass = NULL;

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine (context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine (context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine2);
#endif
	engine3 = jcat_context_get_engine (context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine3);
	engine4 = jcat_context_get_engine (context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null (engine4);
	g_clear_error (&error);

	/* verify blob */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	fn_sig = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes (fn_sig, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_sig);
	blob = jcat_blob_new (JCAT_BLOB_KIND_PKCS7, data_sig);
	jcat_item_add_blob (item, blob);
	results_pass = jcat_context_verify_item (context, data_fwbin, item,
						 JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						 JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE,
						 &error);
	g_assert_no_error (error);
	g_assert_nonnull (results_pass);
	g_assert_cmpint (results_pass->len, ==, 1);
	result = g_ptr_array_index (results_pass, 0);
	g_assert_cmpint (jcat_result_get_timestamp (result), >= , 1502871248);
	g_assert_cmpstr (jcat_result_get_authority (result), == , "O=Linux Vendor Firmware Project,CN=LVFS CA");

	/* enforce a checksum */
	results_fail = jcat_context_verify_item (context, data_fwbin, item,
						 JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						 JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM,
						 &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null (results_fail);
	g_clear_error (&error);
#else
	g_test_skip ("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_item_csum_func (void)
{
#ifdef ENABLE_PKCS7
	JcatResult *result;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	g_autoptr(JcatItem) item = jcat_item_new ("filename.bin");
	g_autoptr(JcatContext) context = jcat_context_new ();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(GPtrArray) results_fail = NULL;
	g_autoptr(GPtrArray) results_pass = NULL;
	const gchar *sig_actual = "a196504d09871da4f7d83b874b500f8ee6e0619ab799f074814b316d88f96f7f";

	/* set up context */
	jcat_context_set_keyring_path (context, "/tmp");
	pki_dir = g_test_build_filename (G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys (context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine (context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine (context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine2);
#endif
	engine3 = jcat_context_get_engine (context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error (error);
	g_assert_nonnull (engine3);
	engine4 = jcat_context_get_engine (context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null (engine4);
	g_clear_error (&error);

	/* verify blob */
	fn_pass = g_test_build_filename (G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes (fn_pass, &error);
	g_assert_no_error (error);
	g_assert_nonnull (data_fwbin);
	blob = jcat_blob_new_utf8 (JCAT_BLOB_KIND_SHA256, sig_actual);
	jcat_item_add_blob (item, blob);
	results_pass = jcat_context_verify_item (context, data_fwbin, item,
						 JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						 JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM,
						 &error);
	g_assert_no_error (error);
	g_assert_nonnull (results_pass);
	g_assert_cmpint (results_pass->len, ==, 1);
	result = g_ptr_array_index (results_pass, 0);
	g_assert_cmpint (jcat_result_get_timestamp (result), == , 0);
	g_assert_cmpstr (jcat_result_get_authority (result), == , NULL);

	/* enforce a signature */
	results_fail = jcat_context_verify_item (context, data_fwbin, item,
						 JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						 JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE,
						 &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null (results_fail);
	g_clear_error (&error);
#else
	g_test_skip ("no GnuTLS support enabled");
#endif
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	/* only critical and error are fatal */
	g_log_set_fatal_mask (NULL, G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	g_test_add_func ("/jcat/blob", jcat_blob_func);
	g_test_add_func ("/jcat/item", jcat_item_func);
	g_test_add_func ("/jcat/file", jcat_file_func);
	g_test_add_func ("/jcat/engine{sha1}", jcat_sha1_engine_func);
	g_test_add_func ("/jcat/engine{sha256}", jcat_sha256_engine_func);
	g_test_add_func ("/jcat/engine{gpg}", jcat_gpg_engine_func);
	g_test_add_func ("/jcat/engine{gpg-msg}", jcat_gpg_engine_msg_func);
	g_test_add_func ("/jcat/engine{pkcs7}", jcat_pkcs7_engine_func);
	g_test_add_func ("/jcat/engine{pkcs7-self-signed}", jcat_pkcs7_engine_self_signed_func);
	g_test_add_func ("/jcat/context{verify-blob}", jcat_context_verify_blob_func);
	g_test_add_func ("/jcat/context{verify-item-sign}", jcat_context_verify_item_sign_func);
	g_test_add_func ("/jcat/context{verify-item-csum}", jcat_context_verify_item_csum_func);
	return g_test_run ();
}
