/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <string.h>

#include "jcat-blob-private.h"
#include "jcat-bt-checkpoint-private.h"
#include "jcat-bt-verifier-private.h"
#include "jcat-common-private.h"
#include "jcat-context.h"
#include "jcat-engine-private.h"
#include "jcat-file.h"
#include "jcat-item-private.h"
#include "jcat-result-private.h"

static void
jcat_blob_func(void)
{
	g_autofree gchar *str = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	const gchar *str_perfect = "JcatBlob:\n"
				   "  Kind:                  gpg\n"
				   "  Flags:                 is-utf8\n"
				   "  AppstreamId:           org.fwupd\n"
				   "  Timestamp:             1970-01-01T03:25:45Z\n"
				   "  Size:                  0x5\n"
				   "  Data:                  BEGIN\n";

	/* enums */
	for (guint i = JCAT_BLOB_KIND_UNKNOWN + 1; i < JCAT_BLOB_KIND_LAST; i++) {
		const gchar *tmp = jcat_blob_kind_to_string(i);
		g_assert_nonnull(tmp);
		g_assert_cmpint(jcat_blob_kind_from_string(tmp), ==, i);
	}
	for (guint i = JCAT_BLOB_KIND_UNKNOWN + 1; i < JCAT_BLOB_KIND_LAST; i++) {
		const gchar *tmp = jcat_blob_kind_to_filename_ext(i);
		g_assert_nonnull(tmp);
	}

	/* sanity check */
	blob = jcat_blob_new_utf8(JCAT_BLOB_KIND_GPG, "BEGIN");
	g_assert_cmpint(jcat_blob_get_kind(blob), ==, JCAT_BLOB_KIND_GPG);
	g_assert_nonnull(jcat_blob_get_data(blob));
	jcat_blob_set_appstream_id(blob, "org.fwupd");
	g_assert_cmpstr(jcat_blob_get_appstream_id(blob), ==, "org.fwupd");
	jcat_blob_set_timestamp(blob, 12345);
	g_assert_cmpint(jcat_blob_get_timestamp(blob), ==, 12345);

	/* to string */
	str = jcat_blob_to_string(blob);
	g_print("%s", str);
	g_assert_cmpstr(str, ==, str_perfect);
}

static void
jcat_item_func(void)
{
	g_autofree gchar *str = NULL;
	g_autoptr(JcatItem) item = NULL;
	const gchar *str_perfect = "JcatItem:\n"
				   "  ID:                    filename.bin\n"
				   "  AliasId:               foo.bin\n";

	/* sanity check */
	item = jcat_item_new("filename.bin");
	jcat_item_add_alias_id(item, "foo.bin");
	jcat_item_add_alias_id(item, "bar.bin");
	jcat_item_remove_alias_id(item, "bar.bin");
	g_assert_cmpstr(jcat_item_get_id(item), ==, "filename.bin");

	/* to string */
	str = jcat_item_to_string(item);
	g_print("%s", str);
	g_assert_cmpstr(str, ==, str_perfect);
}

static void
jcat_file_func(void)
{
	gboolean ret;
	g_autofree gchar *json1 = NULL;
	g_autofree gchar *json2 = NULL;
	g_autoptr(GBytes) data = g_bytes_new("hello world", 12);
	g_autoptr(GError) error = NULL;
	g_autoptr(GFile) gfile = g_file_new_for_path("/tmp/firmware.jcat");
	g_autoptr(GPtrArray) blobs0 = NULL;
	g_autoptr(GPtrArray) blobs1 = NULL;
	g_autoptr(GPtrArray) blobs2 = NULL;
	g_autoptr(GPtrArray) blobs3 = NULL;
	g_autoptr(GPtrArray) items0 = NULL;
	g_autoptr(GPtrArray) items1 = NULL;
	g_autoptr(JcatBlob) blob1 = jcat_blob_new_utf8(JCAT_BLOB_KIND_GPG, "BEGIN");
	g_autoptr(JcatBlob) blob2 = jcat_blob_new(JCAT_BLOB_KIND_SHA256, data);
	g_autoptr(JcatFile) file2 = jcat_file_new();
	g_autoptr(JcatFile) file = jcat_file_new();
	g_autoptr(JcatItem) item1 = NULL;
	g_autoptr(JcatItem) item2 = NULL;
	g_autoptr(JcatItem) item3 = NULL;
	g_autoptr(JcatItem) item = jcat_item_new("firmware.bin");
	const gchar *json_perfect = "{\n"
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
	g_assert(jcat_blob_get_data(blob2) == data);
	jcat_blob_set_appstream_id(blob1, "org.fwupd");
	g_assert_cmpstr(jcat_blob_get_appstream_id(blob1), ==, "org.fwupd");
	jcat_blob_set_timestamp(blob1, 0);
	g_assert_cmpint(jcat_blob_get_timestamp(blob1), ==, 0);
	jcat_blob_set_timestamp(blob2, 0);
	g_assert_cmpint(jcat_blob_get_timestamp(blob2), ==, 0);

	/* get default item */
	item1 = jcat_file_get_item_default(file, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null(item1);
	g_clear_error(&error);

	/* check item */
	g_assert_cmpstr(jcat_item_get_id(item), ==, "firmware.bin");
	blobs0 = jcat_item_get_blobs(item);
	g_assert_cmpint(blobs0->len, ==, 0);
	jcat_item_add_blob(item, blob1);
	jcat_item_add_blob(item, blob2);
	jcat_item_add_blob(item, blob2);
	jcat_item_add_alias_id(item, "foo.bin");
	blobs1 = jcat_item_get_blobs(item);
	g_assert_cmpint(blobs1->len, ==, 2);
	blobs2 = jcat_item_get_blobs_by_kind(item, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint(blobs2->len, ==, 1);
	blobs3 = jcat_item_get_blobs_by_kind(item, JCAT_BLOB_KIND_PKCS7);
	g_assert_cmpint(blobs3->len, ==, 0);

	/* check file */
	g_assert_cmpint(jcat_file_get_version_major(file), ==, 0);
	g_assert_cmpint(jcat_file_get_version_minor(file), ==, 1);
	items0 = jcat_file_get_items(file);
	g_assert_cmpint(items0->len, ==, 0);
	jcat_file_add_item(file, item);
	items1 = jcat_file_get_items(file);
	g_assert_cmpint(items1->len, ==, 1);
	item1 = jcat_file_get_item_by_id(file, "firmware.bin", &error);
	g_assert_no_error(error);
	g_assert_nonnull(item1);
	g_assert(item == item1);
	item2 = jcat_file_get_item_by_id(file, "dave.bin", &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null(item2);
	g_clear_error(&error);

	/* get default item */
	item3 = jcat_file_get_item_default(file, &error);
	g_assert_no_error(error);
	g_assert_nonnull(item3);

	/* export as string */
	json1 = jcat_file_export_json(file, JCAT_EXPORT_FLAG_NONE, &error);
	g_print("%s\n", json1);
	g_assert_cmpstr(json1, ==, json_perfect);

	/* export as compressed file */
	ret = jcat_file_export_file(file, gfile, JCAT_EXPORT_FLAG_NONE, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	/* load compressed file */
	ret = jcat_file_import_file(file2, gfile, JCAT_IMPORT_FLAG_NONE, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	json2 = jcat_file_export_json(file2, JCAT_EXPORT_FLAG_NO_TIMESTAMP, &error);
	g_print("%s\n", json2);
	g_assert_cmpstr(json2, ==, json1);
}

static void
jcat_sha1_engine_func(void)
{
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *sig = NULL;
	g_autoptr(GBytes) blob_sig1 = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob_sig2 = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *sig_actual = "7c0ae84b191822bcadbdcbe2f74a011695d783c7";

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA1, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_SHA1);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_CHECKSUM);

	/* verify checksum */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	blob_sig1 = g_bytes_new_static(sig_actual, strlen(sig_actual));
	result_pass =
	    jcat_engine_self_verify(engine, data_fwbin, blob_sig1, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(result_pass);
	g_assert_cmpint(jcat_result_get_timestamp(result_pass), ==, 0);
	g_assert_cmpstr(jcat_result_get_authority(result_pass), ==, NULL);

	/* verify will fail */
	fn_fail = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes(fn_fail, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fail);
	result_fail =
	    jcat_engine_self_verify(engine, data_fail, blob_sig1, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);

	/* verify signing */
	blob_sig2 = jcat_engine_self_sign(engine, data_fwbin, JCAT_SIGN_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob_sig2);
	sig = jcat_blob_get_data_as_string(blob_sig2);
	g_assert_cmpstr(sig, ==, sig_actual);

	/* not supported */
	jcat_context_blob_kind_disallow(context, JCAT_BLOB_KIND_SHA1);
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA1, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null(engine);
}

static void
jcat_sha256_engine_func(void)
{
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *sig = NULL;
	g_autoptr(GBytes) blob_sig1 = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob_sig2 = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *sig_actual =
	    "a196504d09871da4f7d83b874b500f8ee6e0619ab799f074814b316d88f96f7f";

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_SHA256);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_CHECKSUM);

	/* verify checksum */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	blob_sig1 = g_bytes_new_static(sig_actual, strlen(sig_actual));
	result_pass =
	    jcat_engine_self_verify(engine, data_fwbin, blob_sig1, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(result_pass);
	g_assert_cmpint(jcat_result_get_timestamp(result_pass), ==, 0);
	g_assert_cmpstr(jcat_result_get_authority(result_pass), ==, NULL);

	/* verify will fail */
	fn_fail = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes(fn_fail, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fail);
	result_fail =
	    jcat_engine_self_verify(engine, data_fail, blob_sig1, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);

	/* verify signing */
	blob_sig2 = jcat_engine_self_sign(engine, data_fwbin, JCAT_SIGN_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob_sig2);
	sig = jcat_blob_get_data_as_string(blob_sig2);
	g_assert_cmpstr(sig, ==, sig_actual);
}

static void
jcat_gpg_engine_func(void)
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
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;
	const gchar *str_perfect = "JcatGpgEngine:\n"
				   "  Kind:                  gpg\n"
				   "  VerifyKind:            signature\n";
	const gchar *sig_actual = "-----BEGIN PGP SIGNATURE-----\n"
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
	jcat_context_set_keyring_path(context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* to string */
	str = jcat_engine_to_string(engine);
	g_print("%s", str);
	g_assert_cmpstr(str, ==, str_perfect);

	/* verify with GnuPG */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	data_sig = g_bytes_new_static(sig_actual, strlen(sig_actual));
	result_pass =
	    jcat_engine_pubkey_verify(engine, data_fwbin, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(result_pass);
	g_assert_cmpint(jcat_result_get_timestamp(result_pass), ==, 1438072952);
	g_assert_cmpstr(jcat_result_get_authority(result_pass),
			==,
			"3FC6B804410ED0840D8F2F9748A6D80E4538BAC2");

	/* verify will fail with GnuPG */
	fn_fail = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes(fn_fail, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fail);
	result_fail =
	    jcat_engine_pubkey_verify(engine, data_fail, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);
#else
	g_test_skip("no GnuPG support enabled");
#endif
}

static void
jcat_gpg_engine_msg_func(void)
{
#ifdef ENABLE_GPG
	g_autofree gchar *fn = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result = NULL;
	const gchar *sig = "-----BEGIN PGP MESSAGE-----\n"
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
	jcat_context_set_keyring_path(context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_GPG);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* verify with GnuPG, which should fail as the signature is not a
	 * detached signature at all, but gnupg stabs us in the back by returning
	 * success from gpgme_op_verify() with an empty list of signatures */
	fn = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data = jcat_get_contents_bytes(fn, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data);
	data_sig = g_bytes_new_static(sig, strlen(sig));
	result = jcat_engine_pubkey_verify(engine, data, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_assert_null(result);
#else
	g_test_skip("no GnuPG support enabled");
#endif
}

static void
jcat_pkcs7_engine_func(void)
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
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_PKCS7);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* verify with a signature from the old LVFS */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	fn_sig = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes(fn_sig, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_sig);
	result_pass = jcat_engine_pubkey_verify(engine,
						data_fwbin,
						data_sig,
						JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS,
						&error);
	g_assert_no_error(error);
	g_assert_nonnull(result_pass);
	g_assert_cmpint(jcat_result_get_timestamp(result_pass), >=, 1502871248);
	g_assert_cmpstr(jcat_result_get_authority(result_pass),
			==,
			"O=Linux Vendor Firmware Project,CN=LVFS CA");

	/* verify will fail with a self-signed signature */
	sig_fn2 = g_test_build_filename(G_TEST_BUILT, "colorhug", "firmware.bin.p7c", NULL);
	blob_sig2 = jcat_get_contents_bytes(sig_fn2, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob_sig2);
	result_fail =
	    jcat_engine_pubkey_verify(engine, data_fwbin, blob_sig2, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);

	/* verify will fail with valid signature and different data */
	fn_fail = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes(fn_fail, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fail);
	result_fail =
	    jcat_engine_pubkey_verify(engine, data_fail, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_pkcs7_engine_self_signed_func(void)
{
#ifdef ENABLE_PKCS7
	static const char payload_str[] = "Hello, world!";
	g_autofree gchar *str = NULL;
	g_autoptr(JcatBlob) signature = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatEngine) engine2 = NULL;
	g_autoptr(JcatResult) result = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GError) error = NULL;
	const gchar *str_perfect = "JcatResult:\n"
				   "  Timestamp:             1970-01-01T03:25:45Z\n"
				   "  JcatPkcs7Engine:\n"
				   "    Kind:                pkcs7\n"
				   "    VerifyKind:          signature\n";

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp");

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);

	payload = g_bytes_new_static(payload_str, sizeof(payload_str));
	g_assert_nonnull(payload);
	signature = jcat_engine_self_sign(engine, payload, JCAT_SIGN_FLAG_ADD_TIMESTAMP, &error);
	g_assert_no_error(error);
	g_assert_nonnull(signature);
	result = jcat_engine_self_verify(engine,
					 payload,
					 jcat_blob_get_data(signature),
					 JCAT_VERIFY_FLAG_NONE,
					 &error);
	g_assert_no_error(error);
	g_assert_nonnull(result);

	/* verify engine set */
	engine2 = jcat_result_get_engine(result);
	g_assert(engine == engine2);

	/* to string */
	g_object_set(result, "timestamp", (gint64)12345, NULL);
	str = jcat_result_to_string(result);
	g_print("%s", str);
	g_assert_cmpstr(str, ==, str_perfect);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_ed25519_engine_func(void)
{
#ifdef ENABLE_ED25519
	g_autofree gchar *fn_fail = NULL;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *fn_sig = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fail = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result_fail = NULL;
	g_autoptr(JcatResult) result_pass = NULL;

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp/libjcat-self-test/var");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_ED25519, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_ED25519);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	/* verify with a manually generated signature */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	fn_sig = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.ed25519", NULL);
	data_sig = jcat_get_contents_bytes(fn_sig, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_sig);
	result_pass =
	    jcat_engine_pubkey_verify(engine, data_fwbin, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_nonnull(result_pass);

	/* verify will fail with valid signature and different data */
	fn_fail = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.asc", NULL);
	data_fail = jcat_get_contents_bytes(fn_fail, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fail);
	result_fail =
	    jcat_engine_pubkey_verify(engine, data_fail, data_sig, JCAT_VERIFY_FLAG_NONE, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
	g_assert_null(result_fail);
	g_clear_error(&error);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_ed25519_engine_self_signed_func(void)
{
#ifdef ENABLE_ED25519
	static const char payload_str[] = "Hello, world!";
	g_autofree gchar *str = NULL;
	g_autoptr(JcatBlob) signature = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatEngine) engine2 = NULL;
	g_autoptr(JcatResult) result = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GError) error = NULL;
	const gchar *str_perfect = "JcatResult:\n"
				   "  Timestamp:             1970-01-01T03:25:45Z\n"
				   "  JcatEd25519Engine:\n"
				   "    Kind:                ed25519\n"
				   "    VerifyKind:          signature\n";

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp");

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_ED25519, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);

	payload = g_bytes_new_static(payload_str, sizeof(payload_str));
	g_assert_nonnull(payload);
	signature = jcat_engine_self_sign(engine, payload, JCAT_SIGN_FLAG_ADD_TIMESTAMP, &error);
	g_assert_no_error(error);
	g_assert_nonnull(signature);
	result = jcat_engine_self_verify(engine,
					 payload,
					 jcat_blob_get_data(signature),
					 JCAT_VERIFY_FLAG_NONE,
					 &error);
	g_assert_no_error(error);
	g_assert_nonnull(result);

	/* verify engine set */
	engine2 = jcat_result_get_engine(result);
	g_assert(engine == engine2);

	/* to string */
	g_object_set(result, "timestamp", (gint64)12345, NULL);
	str = jcat_result_to_string(result);
	g_print("%s", str);
	g_assert_cmpstr(str, ==, str_perfect);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_blob_func(void)
{
#ifdef ENABLE_PKCS7
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *fn_sig = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GBytes) data_sig = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(JcatResult) result = NULL;
	g_autoptr(JcatResult) result_disallow = NULL;

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine(context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine2);
#endif
	engine3 = jcat_context_get_engine(context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine3);
	engine4 = jcat_context_get_engine(context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null(engine4);
	g_clear_error(&error);

	/* verify blob */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	fn_sig = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes(fn_sig, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_sig);
	blob = jcat_blob_new(JCAT_BLOB_KIND_PKCS7, data_sig);
	result = jcat_context_verify_blob(context,
					  data_fwbin,
					  blob,
					  JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS,
					  &error);
	g_assert_no_error(error);
	g_assert_nonnull(result);
	g_assert_cmpint(jcat_result_get_timestamp(result), >=, 1502871248);
	g_assert_cmpstr(jcat_result_get_authority(result),
			==,
			"O=Linux Vendor Firmware Project,CN=LVFS CA");

	/* not supported */
	jcat_context_blob_kind_disallow(context, JCAT_BLOB_KIND_PKCS7);
	result_disallow = jcat_context_verify_blob(context,
						   data_fwbin,
						   blob,
						   JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS,
						   &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null(result_disallow);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_item_sign_func(void)
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
	g_autoptr(JcatItem) item = jcat_item_new("filename.bin");
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(GPtrArray) results_fail = NULL;
	g_autoptr(GPtrArray) results_pass = NULL;

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine(context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine2);
#endif
	engine3 = jcat_context_get_engine(context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine3);
	engine4 = jcat_context_get_engine(context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null(engine4);
	g_clear_error(&error);

	/* verify blob */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	fn_sig = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin.p7b", NULL);
	data_sig = jcat_get_contents_bytes(fn_sig, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_sig);
	blob = jcat_blob_new(JCAT_BLOB_KIND_PKCS7, data_sig);
	jcat_item_add_blob(item, blob);
	results_pass = jcat_context_verify_item(context,
						data_fwbin,
						item,
						JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						    JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE,
						&error);
	g_assert_no_error(error);
	g_assert_nonnull(results_pass);
	g_assert_cmpint(results_pass->len, ==, 1);
	result = g_ptr_array_index(results_pass, 0);
	g_assert_cmpint(jcat_result_get_timestamp(result), >=, 1502871248);
	g_assert_cmpstr(jcat_result_get_authority(result),
			==,
			"O=Linux Vendor Firmware Project,CN=LVFS CA");

	/* enforce a checksum */
	results_fail = jcat_context_verify_item(context,
						data_fwbin,
						item,
						JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						    JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM,
						&error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null(results_fail);
	g_clear_error(&error);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_context_verify_item_csum_func(void)
{
#ifdef ENABLE_PKCS7
	JcatResult *result;
	g_autofree gchar *fn_pass = NULL;
	g_autofree gchar *pki_dir = NULL;
	g_autoptr(GBytes) data_fwbin = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBlob) blob = NULL;
	g_autoptr(JcatItem) item = jcat_item_new("filename.bin");
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine1 = NULL;
#ifdef ENABLE_GPG
	g_autoptr(JcatEngine) engine2 = NULL;
#endif
	g_autoptr(JcatEngine) engine3 = NULL;
	g_autoptr(JcatEngine) engine4 = NULL;
	g_autoptr(GPtrArray) results_fail = NULL;
	g_autoptr(GPtrArray) results_pass = NULL;
	const gchar *sig_actual =
	    "a196504d09871da4f7d83b874b500f8ee6e0619ab799f074814b316d88f96f7f";

	/* set up context */
	jcat_context_set_keyring_path(context, "/tmp");
	pki_dir = g_test_build_filename(G_TEST_DIST, "pki", NULL);
	jcat_context_add_public_keys(context, pki_dir);

	/* get all engines */
	engine1 = jcat_context_get_engine(context, JCAT_BLOB_KIND_SHA256, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine1);
#ifdef ENABLE_GPG
	engine2 = jcat_context_get_engine(context, JCAT_BLOB_KIND_GPG, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine2);
#endif
	engine3 = jcat_context_get_engine(context, JCAT_BLOB_KIND_PKCS7, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine3);
	engine4 = jcat_context_get_engine(context, JCAT_BLOB_KIND_LAST, &error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
	g_assert_null(engine4);
	g_clear_error(&error);

	/* verify blob */
	fn_pass = g_test_build_filename(G_TEST_DIST, "colorhug", "firmware.bin", NULL);
	data_fwbin = jcat_get_contents_bytes(fn_pass, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data_fwbin);
	blob = jcat_blob_new_utf8(JCAT_BLOB_KIND_SHA256, sig_actual);
	jcat_item_add_blob(item, blob);
	results_pass = jcat_context_verify_item(context,
						data_fwbin,
						item,
						JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						    JCAT_VERIFY_FLAG_REQUIRE_CHECKSUM,
						&error);
	g_assert_no_error(error);
	g_assert_nonnull(results_pass);
	g_assert_cmpint(results_pass->len, ==, 1);
	result = g_ptr_array_index(results_pass, 0);
	g_assert_cmpint(jcat_result_get_timestamp(result), ==, 0);
	g_assert_cmpstr(jcat_result_get_authority(result), ==, NULL);

	/* enforce a signature */
	results_fail = jcat_context_verify_item(context,
						data_fwbin,
						item,
						JCAT_VERIFY_FLAG_DISABLE_TIME_CHECKS |
						    JCAT_VERIFY_FLAG_REQUIRE_SIGNATURE,
						&error);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	g_assert_null(results_fail);
	g_clear_error(&error);
#else
	g_test_skip("no GnuTLS support enabled");
#endif
}

static void
jcat_bt_verifier_func(void)
{
	GBytes *buf;
	g_autofree gchar *fn = NULL;
	g_autofree gchar *str = NULL;
	g_autoptr(GBytes) blob = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBtVerifier) btverifier = NULL;

	fn = g_test_build_filename(G_TEST_DIST, "test.btverifier", NULL);
	blob = jcat_get_contents_bytes(fn, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob);

	btverifier = jcat_bt_verifier_new(blob, &error);
	g_assert_no_error(error);
	g_assert_nonnull(btverifier);

	str = jcat_bt_verifier_to_string(btverifier);
	g_print("%s\n", str);

	g_assert_cmpstr(jcat_bt_verifier_get_name(btverifier), ==, "lvfsqa");
	g_assert_cmpstr(jcat_bt_verifier_get_hash(btverifier), ==, "c463f084");
	g_assert_cmpint(jcat_bt_verifier_get_alg(btverifier), ==, 1);
	buf = jcat_bt_verifier_get_key(btverifier);
	g_assert_cmpint(g_bytes_get_size(buf), ==, 32);
}

static void
jcat_bt_checkpoint_func(void)
{
	GBytes *buf;
	g_autofree gchar *fn = NULL;
	g_autofree gchar *str = NULL;
	g_autoptr(GBytes) blob = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JcatBtCheckpoint) btcheckpoint = NULL;

	fn = g_test_build_filename(G_TEST_DIST, "test.btcheckpoint", NULL);
	blob = jcat_get_contents_bytes(fn, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob);

	btcheckpoint = jcat_bt_checkpoint_new(blob, &error);
	g_assert_no_error(error);
	g_assert_nonnull(btcheckpoint);

	str = jcat_bt_checkpoint_to_string(btcheckpoint);
	g_print("%s\n", str);

	g_assert_cmpstr(jcat_bt_checkpoint_get_origin(btcheckpoint), ==, "lvfsqa");
	g_assert_cmpstr(jcat_bt_checkpoint_get_identity(btcheckpoint), ==, "lvfsqa");
	g_assert_cmpstr(jcat_bt_checkpoint_get_hash(btcheckpoint), ==, "c463f084");
	g_assert_cmpint(jcat_bt_checkpoint_get_log_size(btcheckpoint), ==, 4);
	buf = jcat_bt_checkpoint_get_pubkey(btcheckpoint);
	g_assert_cmpint(g_bytes_get_size(buf), ==, 32);
	buf = jcat_bt_checkpoint_get_signature(btcheckpoint);
	g_assert_cmpint(g_bytes_get_size(buf), ==, 64);
	buf = jcat_bt_checkpoint_get_payload(btcheckpoint);
	g_assert_cmpint(g_bytes_get_size(buf), ==, 54);
}

static void
jcat_bt_common_func(void)
{
	gboolean ret;
	g_autofree gchar *fn_btcheckpoint = NULL;
	g_autofree gchar *fn_btverifier = NULL;
	g_autoptr(GBytes) blob_btcheckpoint = NULL;
	g_autoptr(GBytes) blob_btverifier = NULL;
	g_autoptr(JcatBtCheckpoint) btcheckpoint = NULL;
	g_autoptr(JcatBtVerifier) btverifier = NULL;
	g_autoptr(JcatContext) context = jcat_context_new();
	g_autoptr(JcatEngine) engine = NULL;
	g_autoptr(JcatResult) result = NULL;
	g_autoptr(GError) error = NULL;

	fn_btverifier = g_test_build_filename(G_TEST_DIST, "test.btverifier", NULL);
	blob_btverifier = jcat_get_contents_bytes(fn_btverifier, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob_btverifier);

	btverifier = jcat_bt_verifier_new(blob_btverifier, &error);
	g_assert_no_error(error);
	g_assert_nonnull(btverifier);

	fn_btcheckpoint = g_test_build_filename(G_TEST_DIST, "test.btcheckpoint", NULL);
	blob_btcheckpoint = jcat_get_contents_bytes(fn_btcheckpoint, &error);
	g_assert_no_error(error);
	g_assert_nonnull(blob_btcheckpoint);

	btcheckpoint = jcat_bt_checkpoint_new(blob_btcheckpoint, &error);
	g_assert_no_error(error);
	g_assert_nonnull(btcheckpoint);

	/* get engine */
	engine = jcat_context_get_engine(context, JCAT_BLOB_KIND_ED25519, &error);
	g_assert_no_error(error);
	g_assert_nonnull(engine);
	g_assert_cmpint(jcat_engine_get_kind(engine), ==, JCAT_BLOB_KIND_ED25519);
	g_assert_cmpint(jcat_engine_get_method(engine), ==, JCAT_BLOB_METHOD_SIGNATURE);

	ret = jcat_engine_add_public_key_raw(engine, jcat_bt_verifier_get_key(btverifier), &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	// TODO: check jcat_bt_checkpoint_get_origin == jcat_bt_verifier_get_name
	// TODO: check jcat_bt_checkpoint_get_identity == jcat_bt_verifier_get_name
	result = jcat_engine_pubkey_verify(engine,
					   jcat_bt_checkpoint_get_payload(btcheckpoint),
					   jcat_bt_checkpoint_get_signature(btcheckpoint),
					   JCAT_VERIFY_FLAG_NONE,
					   &error);
	g_assert_no_error(error);
	g_assert_nonnull(result);
}

static gchar *
jcat_rfc6962_decode_string(GByteArray *buf)
{
	GString *str = g_string_new(NULL);
	for (guint i = 0; i < buf->len; i++)
		g_string_append_printf(str, "%02x", buf->data[i]);
	return g_string_free(str, FALSE);
}

#define RFC6962_LEAF_HASH_PREFIX 0x00
#define RFC6962_NODE_HASH_PREFIX 0x01

static GByteArray *
jcat_rfc6962_hash_leaf(GByteArray *buf)
{
	gsize digest_len = 32;
	guint8 buffer[32] = {0x0};
	guint8 idx = RFC6962_LEAF_HASH_PREFIX;
	g_autoptr(GChecksum) csum = g_checksum_new(G_CHECKSUM_SHA256);
	g_autoptr(GByteArray) outbuf = g_byte_array_new();

	g_checksum_update(csum, (const guchar *)&idx, sizeof(idx));
	g_checksum_update(csum, (const guchar *)buf->data, buf->len);

	g_checksum_get_digest(csum, buffer, &digest_len);
	g_byte_array_append(outbuf, buffer, sizeof(buffer));
	return g_steal_pointer(&outbuf);
}

static GByteArray *
jcat_rfc6962_hash_children(GByteArray *lbuf, GByteArray *rbuf)
{
	gsize digest_len = 32;
	guint8 buffer[32] = {0x0};
	guint8 idx = RFC6962_NODE_HASH_PREFIX;
	g_autoptr(GChecksum) csum = g_checksum_new(G_CHECKSUM_SHA256);
	g_autoptr(GByteArray) outbuf = g_byte_array_new();

	g_checksum_update(csum, (const guchar *)&idx, sizeof(idx));
	g_checksum_update(csum, (const guchar *)lbuf->data, lbuf->len);
	g_checksum_update(csum, (const guchar *)rbuf->data, rbuf->len);

	g_checksum_get_digest(csum, buffer, &digest_len);
	g_byte_array_append(outbuf, buffer, sizeof(buffer));
	return g_steal_pointer(&outbuf);
}

static void
jcat_rfc6962_func(void)
{
	const gchar *leaf_data = "L123456";
	const gchar *node_data_l = "N123";
	const gchar *node_data_r = "N456";
	g_autofree gchar *csum_empty_leaf_str = NULL;
	g_autofree gchar *csum_empty_str = NULL;
	g_autofree gchar *csum_leaf_str = NULL;
	g_autofree gchar *csum_node_str = NULL;
	g_autofree gchar *csum_node_swapped_str = NULL;
	g_autoptr(GByteArray) buf = g_byte_array_new();
	g_autoptr(GByteArray) buf_l = g_byte_array_new();
	g_autoptr(GByteArray) buf_r = g_byte_array_new();
	g_autoptr(GByteArray) csum_empty_leaf = NULL;
	g_autoptr(GByteArray) csum_leaf = NULL;
	g_autoptr(GByteArray) csum_node = NULL;
	g_autoptr(GByteArray) csum_node_swapped = NULL;

	/* RFC6962 Empty */
	csum_empty_str = g_compute_checksum_for_data(G_CHECKSUM_SHA256, NULL, 0);
	g_assert_cmpstr(csum_empty_str,
			==,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	/* RFC6962 Empty Leaf */
	csum_empty_leaf = jcat_rfc6962_hash_leaf(buf);
	csum_empty_leaf_str = jcat_rfc6962_decode_string(csum_empty_leaf);
	g_assert_cmpstr(csum_empty_leaf_str,
			==,
			"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");

	/* RFC6962 Leaf */
	g_byte_array_append(buf, (const guint8 *)leaf_data, strlen(leaf_data));
	csum_leaf = jcat_rfc6962_hash_leaf(buf);
	csum_leaf_str = jcat_rfc6962_decode_string(csum_leaf);
	g_assert_cmpstr(csum_leaf_str,
			==,
			"395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56");

	/* RFC6962 Node */
	g_byte_array_append(buf_l, (const guint8 *)node_data_l, strlen(node_data_l));
	g_byte_array_append(buf_r, (const guint8 *)node_data_r, strlen(node_data_r));
	csum_node = jcat_rfc6962_hash_children(buf_l, buf_r);
	csum_node_str = jcat_rfc6962_decode_string(csum_node);
	g_assert_cmpstr(csum_node_str,
			==,
			"aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb");

	/* RFC6962 Node, swapped */
	csum_node_swapped = jcat_rfc6962_hash_children(buf_r, buf_l);
	csum_node_swapped_str = jcat_rfc6962_decode_string(csum_node_swapped);
	g_assert_cmpstr(csum_node_swapped_str,
			==,
			"013dee051c2516cf8ba3dfc4fae6bfb016587de88cd448f1e96df99ea575257a");
}

static void
_g_set_byte_array(GByteArray **buf, GByteArray *buf_new)
{
	if (buf_new == *buf)
		return;
	g_byte_array_unref(*buf);
	*buf = g_byte_array_ref(buf_new);
}

/*
 * Compute a subtree hash for a node on or below the tree's right border. Assumes `proof` hashes
 * are ordered from lower levels to upper, and `seed` is the initial subtree/leaf hash on the path
 * located at the specified `index` on its level.
 */
static GByteArray *
jcat_hash_chainInner(GByteArray *seed, GPtrArray *proof, gint64 index)
{
	g_autoptr(GByteArray) subtree = g_byte_array_ref(seed);
	for (guint i = 0; i < proof->len; i++) {
		GByteArray *h = g_ptr_array_index(proof, i);
		g_autoptr(GByteArray) subtree_tmp = NULL;

		if (((index >> i) & 1) == 0) {
			subtree_tmp = jcat_rfc6962_hash_children(subtree, h);
		} else {
			subtree_tmp = jcat_rfc6962_hash_children(h, subtree);
		}
		_g_set_byte_array(&subtree, subtree_tmp);
	}
	return g_steal_pointer(&subtree);
}

/*
 * Compute a subtree hash like jcat_hash_chainInner, but only take hashes to the left from the path
 * into consideration, which effectively means the result is a hash of the corresponding earlier
 * version of this subtree.
 */
static GByteArray *
jcat_hash_chainInnerRight(GByteArray *seed, GPtrArray *proof, gint64 index)
{
	g_autoptr(GByteArray) subtree = g_byte_array_ref(seed);
	for (guint i = 0; i < proof->len; i++) {
		GByteArray *h = g_ptr_array_index(proof, i);
		if (((index >> i) & 1) == 1) {
			g_autoptr(GByteArray) subtree_tmp = jcat_rfc6962_hash_children(h, subtree);
			_g_set_byte_array(&subtree, subtree_tmp);
		}
	}
	return g_steal_pointer(&subtree);
}

/*
 * Chains proof hashes along tree borders. This differs from inner chaining because `proof`
 * contains only left-side subtree hashes.
 */
static GByteArray *
jcat_hash_chainBorderRight(GByteArray *seed, GPtrArray *proof)
{
	g_autoptr(GByteArray) subtree = g_byte_array_ref(seed);
	for (guint i = 0; i < proof->len; i++) {
		GByteArray *h = g_ptr_array_index(proof, i);
		g_autoptr(GByteArray) subtree_tmp = jcat_rfc6962_hash_children(h, subtree);
		_g_set_byte_array(&subtree, subtree_tmp);
	}
	return g_steal_pointer(&subtree);
}

/* count number of 1's set */
static guint
bits_OnesCount64(guint64 val)
{
	guint c = 0;
	for (guint i = 0; i < 64; i++) {
		if (val & ((guint64)0b1 << i))
			c += 1;
	}
	return c;
}

/* count number of trailing zeros */
static guint
bits_TrailingZeros64(guint64 val)
{
	//	if (val == 0xFFFFFFFFFFFFFFFF)
	//		return 0;
	for (guint i = 0; i < 64; i++) {
		if (val & ((guint64)0b1 << i))
			return i;
	}
	return 64;
}

/* minimum number of bits required to represent number */
static guint
bits_Len64(guint64 val)
{
	if (val == 0)
		return 0;
	for (guint i = 0; i < 64; i++) {
		if (((guint64)0b1 << i) >= val)
			return i + 1;
	}
	return 64;
}

static guint
innerProofSize(guint64 index, guint64 size)
{
	return bits_Len64(index ^ (size - 1));
}

// decompInclProof breaks down inclusion proof for a leaf at the specified
// |index| in a tree of the specified |size| into 2 components. The splitting
// point between them is where paths to leaves |index| and |size-1| diverge.
// Returns lengths of the bottom and upper proof parts correspondingly. The sum
// of the two determines the correct length of the inclusion proof.
static void
decompInclProof(guint64 index, guint64 size, guint *inner, guint *border)
{
	guint inner_tmp = innerProofSize(index, size);
	if (inner != NULL)
		*inner = inner_tmp;
	if (border != NULL)
		*border = bits_OnesCount64(index >> inner_tmp);
}

static gboolean
fu_common_bytes_compare_raw(const guint8 *buf1,
			    gsize bufsz1,
			    const guint8 *buf2,
			    gsize bufsz2,
			    GError **error)
{
	g_return_val_if_fail(buf1 != NULL, FALSE);
	g_return_val_if_fail(buf2 != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* not the same length */
	if (bufsz1 != bufsz2) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "got %" G_GSIZE_FORMAT " bytes, expected "
			    "%" G_GSIZE_FORMAT,
			    bufsz1,
			    bufsz2);
		return FALSE;
	}

	/* check matches */
	for (guint i = 0x0; i < bufsz1; i++) {
		if (buf1[i] != buf2[i]) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "got 0x%02x, expected 0x%02x @ 0x%04x",
				    buf1[i],
				    buf2[i],
				    i);
			return FALSE;
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_byte_array_compare(GByteArray *buf1, GByteArray *buf2, GError **error)
{
	g_return_val_if_fail(buf1 != NULL, FALSE);
	g_return_val_if_fail(buf2 != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	return fu_common_bytes_compare_raw(buf1->data, buf1->len, buf2->data, buf2->len, error);
}

static GPtrArray *
jcat_rfc6962_proof_slice_left(GPtrArray *src, guint pos, GError **error)
{
	GPtrArray *dst;

	/* sanity check */
	if (pos >= src->len) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "pos %u of %u", pos, src->len);
		return NULL;
	}

	/* copy from 0 to pos, non-inclusive */
	dst = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (guint i = 0; i < src->len && i < pos; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return dst;
}

static GPtrArray *
jcat_rfc6962_proof_slice_right(GPtrArray *src, guint pos, GError **error)
{
	GPtrArray *dst;

	/* sanity check */
	if (pos >= src->len) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "pos %u of %u", pos, src->len);
		return NULL;
	}

	/* copy from 0 to pos, non-inclusive */
	dst = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (guint i = pos; i < src->len; i++) {
		GByteArray *buf = g_ptr_array_index(src, i);
		g_ptr_array_add(dst, g_byte_array_ref(buf));
	}
	return dst;
}

// RootFromInclusionProof calculates the expected tree root given the proof and leaf.
// leafIndex starts at 0.  treeSize is the number of nodes in the tree.
// proof is an array of neighbor nodes from the bottom to the root.
static GByteArray *
RootFromInclusionProof(gint64 leafIndex,
		       gint64 treeSize,
		       GPtrArray *proof,
		       GByteArray *leafHash,
		       GError **error)
{
	guint inner = 0;
	guint border = 0;
	g_autoptr(GByteArray) res = NULL;
	g_autoptr(GPtrArray) proof_left = NULL;
	g_autoptr(GPtrArray) proof_right = NULL;

	if (leafIndex < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leafIndex %u < 0",
			    (guint)leafIndex);
		return NULL;
	}
	if (treeSize < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "treeSize %u < 0",
			    (guint)treeSize);
		return NULL;
	}
	if (leafIndex >= treeSize) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leafIndex is beyond treeSize: %u >= %u",
			    (guint)leafIndex,
			    (guint)treeSize);
		return NULL;
	}
	//	if got, want = len(leafHash), v.hasher.Size(); got != want {
	//		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "leafHash has unexpected
	//size %d, want %d", got, want); 		return FALSE;
	//	}

	decompInclProof(leafIndex, treeSize, &inner, &border);
	if (proof->len != inner + border) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "wrong proof size %u, want %u",
			    (guint)proof->len,
			    (guint)inner + border);
		return NULL;
	}

	proof_left = jcat_rfc6962_proof_slice_left(proof, inner, error);
	if (proof_left == NULL)
		return NULL;
	proof_right = jcat_rfc6962_proof_slice_right(proof, inner, error);
	if (proof_right == NULL)
		return NULL;
	res = jcat_hash_chainInner(leafHash, proof_left, leafIndex);
	return jcat_hash_chainBorderRight(res, proof_right);
}

// VerifyInclusionProof verifies the correctness of the proof given the passed
// in information about the tree and leaf.
static gboolean
VerifyInclusionProof(gint64 leafIndex,
		     guint64 treeSize,
		     GPtrArray *proof,
		     GByteArray *root,
		     GByteArray *leafHash,
		     GError **error)
{
	g_autoptr(GByteArray) calcRoot = NULL;

	calcRoot = RootFromInclusionProof(leafIndex, treeSize, proof, leafHash, error);
	if (calcRoot == NULL)
		return FALSE;

	if (!fu_byte_array_compare(calcRoot, root, error)) {
		g_autofree gchar *str1 = jcat_rfc6962_decode_string(calcRoot);
		g_autofree gchar *str2 = jcat_rfc6962_decode_string(root);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	/* success */
	return TRUE;
}

// VerifyConsistencyProof checks that the passed in consistency proof is valid
// between the passed in tree snapshots. Snapshots are the respective tree
// sizes. Accepts shapshot2 >= snapshot1 >= 0.
static gboolean
VerifyConsistencyProof(gint64 snapshot1,
		       gint64 snapshot2,
		       GByteArray *root1,
		       GByteArray *root2,
		       GPtrArray *proof,
		       GError **error)
{
	guint inner = 0;
	guint border = 0;
	guint shift;
	guint start;
	gint64 mask;
	GByteArray *seed;
	g_autoptr(GPtrArray) proof_left = NULL;
	g_autoptr(GPtrArray) proof_right = NULL;
	g_autoptr(GPtrArray) proof_new = NULL;
	g_autoptr(GByteArray) hash1 = NULL;
	g_autoptr(GByteArray) hash2 = NULL;

	if (snapshot1 < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "snapshot1 (%u) < 0 ",
			    (guint)snapshot1);
		return FALSE;
	}
	if (snapshot2 < snapshot1) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "snapshot2 (%u) < snapshot1 (%u)",
			    (guint)snapshot1,
			    (guint)snapshot2);
		return FALSE;
	}
	if (snapshot1 == snapshot2) {
		if (!fu_byte_array_compare(root1, root2, error)) {
			g_autofree gchar *str1 = jcat_rfc6962_decode_string(root1);
			g_autofree gchar *str2 = jcat_rfc6962_decode_string(root2);
			g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
			return FALSE;
		}
		if (proof->len > 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "root1 and root2 match, but proof is non-empty");
			return FALSE;
		}
		// Proof OK.
		return TRUE;
	}

	if (snapshot1 == 0) {
		// Any snapshot greater than 0 is consistent with snapshot 0.
		if (proof->len > 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "expected empty proof, but got %u components",
				    proof->len);
			return FALSE;
		}
		// Proof OK.
		return TRUE;
	}

	if (proof->len == 0) {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "empty proof");
		return FALSE;
	}

	decompInclProof(snapshot1 - 1, snapshot2, &inner, &border);
	shift = bits_TrailingZeros64((guint64)snapshot1);
	inner -= shift; // Note: shift < inner if snapshot1 < snapshot2.

	// The proof includes the root hash for the sub-tree of size 2^shift.
	if (snapshot1 == 1 << ((guint)shift)) {
		// Unless snapshot1 is that very 2^shift.
		seed = root1;
		start = 0;
	} else {
		seed = g_ptr_array_index(proof, 0);
		start = 1;
	}
	if (proof->len != start + inner + border) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "wrong proof size %u, want %u",
			    proof->len,
			    (guint)(start + inner + border));
		return FALSE;
	}
	proof_new = jcat_rfc6962_proof_slice_right(proof_new, start, error);
	if (proof_new == NULL)
		return FALSE;

	// Now proof->len == inner+border, and proof is effectively a suffix of
	// inclusion proof for entry |snapshot1-1| in a tree of size |snapshot2|.

	// Verify the first root.
	//	ch = hashChainer(v)
	mask = (snapshot1 - 1) >> (guint)shift; // Start chaining from level |shift|.

	proof_left = jcat_rfc6962_proof_slice_left(proof_new, inner, error);
	if (proof_left == NULL)
		return FALSE;
	proof_right = jcat_rfc6962_proof_slice_right(proof_new, inner, error);
	if (proof_right == NULL)
		return FALSE;

	hash1 = jcat_hash_chainInnerRight(seed, proof_left, mask);
	hash1 = jcat_hash_chainBorderRight(hash1, proof_right);
	if (!fu_byte_array_compare(hash1, root1, error)) {
		g_autofree gchar *str1 = jcat_rfc6962_decode_string(hash1);
		g_autofree gchar *str2 = jcat_rfc6962_decode_string(root1);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	// Verify the second root.
	hash2 = jcat_hash_chainInner(seed, proof_left, mask);
	hash2 = jcat_hash_chainBorderRight(hash2, proof_right);
	if (!fu_byte_array_compare(hash2, root2, error)) {
		g_autofree gchar *str1 = jcat_rfc6962_decode_string(hash2);
		g_autofree gchar *str2 = jcat_rfc6962_decode_string(root2);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	// Proof OK.
	return TRUE;
}

// VerifiedPrefixHashFromInclusionProof calculates a root hash over leaves
// [0..subSize), based on the inclusion |proof| and |leafHash| for a leaf at
// index |subSize-1| in a tree of the specified |size| with the passed in
// |root| hash.
// Returns an error if the |proof| verification fails. The resulting smaller
// tree's root hash is trusted iff the bigger tree's |root| hash is trusted.
static GByteArray *
VerifiedPrefixHashFromInclusionProof(gint64 subSize,
				     gint64 size,
				     GPtrArray *proof,
				     GByteArray *root,
				     GByteArray *leafHash,
				     GError **error)
{
	guint inner;
	gint64 leaf;
	g_autoptr(GByteArray) res = NULL;
	g_autoptr(GPtrArray) proof_left = NULL;
	g_autoptr(GPtrArray) proof_right = NULL;

	if (subSize <= 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "subtree size is %u, want > 0",
			    (guint)subSize);
		return NULL;
	}
	leaf = subSize - 1;
	if (!VerifyInclusionProof(leaf, size, proof, root, leafHash, error))
		return NULL;

	inner = innerProofSize(leaf, size);
	proof_left = jcat_rfc6962_proof_slice_left(proof, inner, error);
	if (proof_left == NULL)
		return NULL;
	proof_right = jcat_rfc6962_proof_slice_right(proof, inner, error);
	if (proof_right == NULL)
		return NULL;
	res = jcat_hash_chainInnerRight(leafHash, proof_left, leaf);
	return jcat_hash_chainBorderRight(res, proof_right);
}

static void
jcat_rfc6962_func2(void)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) proof_left = NULL;
	g_autoptr(GPtrArray) proof = NULL;
	g_autoptr(GPtrArray) proof_right = NULL;

	g_assert_cmpint(bits_OnesCount64(0), ==, 0);
	g_assert_cmpint(bits_OnesCount64(1), ==, 1);
	g_assert_cmpint(bits_OnesCount64(5), ==, 2);
	g_assert_cmpint(bits_OnesCount64(5), ==, 2);
	g_assert_cmpint(bits_OnesCount64(0x8000000000000000), ==, 1);
	g_assert_cmpint(bits_OnesCount64(0xFFFFFFFFFFFFFFFF), ==, 64);

	g_assert_cmpint(bits_TrailingZeros64(0), ==, 64);
	g_assert_cmpint(bits_TrailingZeros64(8), ==, 3);
	g_assert_cmpint(bits_TrailingZeros64(24), ==, 3);
	g_assert_cmpint(bits_TrailingZeros64(25), ==, 0);
	g_assert_cmpint(bits_TrailingZeros64(0x8000000000000000), ==, 63);
	g_assert_cmpint(bits_TrailingZeros64(0xFFFFFFFFFFFFFFFF), ==, 0);

	g_assert_cmpint(bits_Len64(0), ==, 0);
	g_assert_cmpint(bits_Len64(1), ==, 1);
	g_assert_cmpint(bits_Len64(16), ==, 5);
	g_assert_cmpint(bits_Len64(64), ==, 7);
	g_assert_cmpint(bits_Len64(0x8000000000000000), ==, 64);
	g_assert_cmpint(bits_Len64(0xFFFFFFFFFFFFFFFF), ==, 64);

	/* left slice */
	proof = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (guint i = 0; i < 9; i++)
		g_ptr_array_add(proof, g_byte_array_new());
	proof_left = jcat_rfc6962_proof_slice_left(proof, 3, &error);
	g_assert_no_error(error);
	g_assert_nonnull(proof_left);
	g_assert_cmpint(proof_left->len, ==, 3);

	/* right slice */
	proof_right = jcat_rfc6962_proof_slice_right(proof, 4, &error);
	g_assert_no_error(error);
	g_assert_nonnull(proof_right);
	g_assert_cmpint(proof_right->len, ==, 5);
}

#if 0
inclusionProofTestVector struct {
	     gint64 leaf;
	 gint64 snapshot;
	    GPtrArray *proof;
}

consistencyTestVector struct {
	gint64 snapshot1;
	gint64 snapshot2;
	GPtrArray *proof;
}

var (
	sha256SomeHash      = dh("abacaba000000000000000000000000000000000000000000060061e00123456", 32)
	sha256EmptyTreeHash = dh("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32)

	inclusionProofs = []inclusionProofTestVector{
		{0, 0, NULL},
		{1, 1, NULL},
		{1, 8, GPtrArray *{
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32),
		}},
		{6, 8, GPtrArray *{
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
		{3, 3, GPtrArray *{
			dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		}},
		{2, 5, GPtrArray *{
			dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
		}},
	}

	consistencyProofs = []consistencyTestVector{
		{1, 1, NULL},
		{1, 8, GPtrArray *{
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32),
		}},
		{6, 8, GPtrArray *{
			dh("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", 32),
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
		{2, 5, GPtrArray *{
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
		}},
	}

	roots = GPtrArray *{
		dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
		dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		dh("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", 32),
		dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		dh("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", 32),
		dh("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", 32),
		dh("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", 32),
		dh("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", 32),
	}

	leaves = GPtrArray *{
		dh("", 0),
		dh("00", 1),
		dh("10", 1),
		dh("2021", 2),
		dh("3031", 2),
		dh("40414243", 4),
		dh("5051525354555657", 8),
		dh("606162636465666768696a6b6c6d6e6f", 16),
	}
)

// inclusionProbe is a parameter set for inclusion proof verification.
type inclusionProbe struct {
	gint64 leafIndex
	gint64 treeSize
	GByteArray *root;
	GByteArray *leafHash;
	GPtrArray *proof;

	desc string
}

// consistencyProbe is a parameter set for consistency proof verification.
type consistencyProbe struct {
	gint64 snapshot1;
	gint64 snapshot2;
	GByteArray *root1;
	GByteArray *root2;
	GPtrArray *proof;

	desc string
}

func corruptInclusionProof(leafIndex, gint64 treeSize, GPtrArray *proof, root, GByteArray *leafHash) []inclusionProbe {
	ret = []inclusionProbe{
		// Wrong leaf index.
		{leafIndex - 1, treeSize, root, leafHash, proof, "leafIndex - 1"},
		{leafIndex + 1, treeSize, root, leafHash, proof, "leafIndex + 1"},
		{leafIndex ^ 2, treeSize, root, leafHash, proof, "leafIndex ^ 2"},
		// Wrong tree height.
		{leafIndex, treeSize * 2, root, leafHash, proof, "treeSize * 2"},
		{leafIndex, treeSize / 2, root, leafHash, proof, "treeSize / 2"},
		// Wrong leaf or root.
		{leafIndex, treeSize, root, GByteArray *("WrongLeaf"), proof, "wrong leaf"},
		{leafIndex, treeSize, sha256EmptyTreeHash, leafHash, proof, "empty root"},
		{leafIndex, treeSize, sha256SomeHash, leafHash, proof, "random root"},
		// Add garbage at the end.
		{leafIndex, treeSize, root, leafHash, extend(proof, GByteArray *{}), "trailing garbage"},
		{leafIndex, treeSize, root, leafHash, extend(proof, root), "trailing root"},
		// Add garbage at the front.
		{leafIndex, treeSize, root, leafHash, prepend(proof, GByteArray *{}), "preceding garbage"},
		{leafIndex, treeSize, root, leafHash, prepend(proof, root), "preceding root"},
	}
	ln = len(proof)

	// Modify single bit in an element of the proof.
	for i = 0; i < ln; i++ {
		wrongProof = prepend(proof)                          // Copy the proof slice.
		wrongProof[i] = append(GByteArray *(NULL), wrongProof[i]...) // But also the modified data.
		wrongProof[i][0] ^= 8                                 // Flip the bit.
		desc = fmt.Sprintf("modified proof[%d] bit 3", i)
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, wrongProof, desc})
	}

	if ln > 0 {
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, proof[:ln-1], "removed component"})
	}
	if ln > 1 {
		wrongProof = prepend(proof[1:], proof[0], sha256SomeHash)
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, wrongProof, "inserted component"})
	}

	return ret
}

func corruptConsistencyProof(gint64 snapshot1, gint64 snapshot2, GByteArray *root1, GByteArray *root2, GPtrArray *proof) []consistencyProbe {
	ln = len(proof)
	ret = []consistencyProbe{
		// Wrong snapshot index.
		{snapshot1 - 1, snapshot2, root1, root2, proof, "snapshot1 - 1"},
		{snapshot1 + 1, snapshot2, root1, root2, proof, "snapshot1 + 1"},
		{snapshot1 ^ 2, snapshot2, root1, root2, proof, "snapshot1 ^ 2"},
		// Wrong tree height.
		{snapshot1, snapshot2 * 2, root1, root2, proof, "snapshot2 * 2"},
		{snapshot1, snapshot2 / 2, root1, root2, proof, "snapshot2 / 2"},
		// Wrong root.
		{snapshot1, snapshot2, GByteArray *("WrongRoot"), root2, proof, "wrong root1"},
		{snapshot1, snapshot2, root1, GByteArray *("WrongRoot"), proof, "wrong root2"},
		{snapshot1, snapshot2, root2, root1, proof, "swapped roots"},
		// Empty proof.
		{snapshot1, snapshot2, root1, root2, GPtrArray *{}, "empty proof"},
		// Add garbage at the end.
		{snapshot1, snapshot2, root1, root2, extend(proof, GByteArray *{}), "trailing garbage"},
		{snapshot1, snapshot2, root1, root2, extend(proof, root1), "trailing root1"},
		{snapshot1, snapshot2, root1, root2, extend(proof, root2), "trailing root2"},
		// Add garbage at the front.
		{snapshot1, snapshot2, root1, root2, prepend(proof, GByteArray *{}), "preceding garbage"},
		{snapshot1, snapshot2, root1, root2, prepend(proof, root1), "preceding root1"},
		{snapshot1, snapshot2, root1, root2, prepend(proof, root2), "preceding root2"},
		{snapshot1, snapshot2, root1, root2, prepend(proof, proof[0]), "preceding proof[0]"},
	}

	// Remove a node from the end.
	if (ln > 0) {
		ret = append(ret, consistencyProbe{snapshot1, snapshot2, root1, root2, proof[:ln-1], "truncated proof"})
	}

	// Modify single bit in an element of the proof.
	for (i = 0; i < ln; i++) {
		wrongProof = prepend(proof)                          // Copy the proof slice.
		wrongProof[i] = append(GByteArray *(NULL), wrongProof[i]...) // But also the modified data.
		wrongProof[i][0] ^= 16                                // Flip the bit.
		desc = fmt.Sprintf("modified proof[%d] bit 4", i)
		ret = append(ret, consistencyProbe{snapshot1, snapshot2, root1, root2, wrongProof, desc})
	}

	return ret
}

func verifierCheck(v *LogVerifier, leafIndex, gint64 treeSize, GPtrArray *proof, root, GByteArray *leafHash, GError **error)
{
	// Verify original inclusion proof.
	got, err = v.RootFromInclusionProof(leafIndex, treeSize, proof, leafHash)
	if err != NULL {
		return err
	}
	if !bytes.Equal(got, root) {
		return fmt.Errorf("got root:\n%x\nexpected:\n%x", got, root)
	}
	if err = v.VerifyInclusionProof(leafIndex, treeSize, proof, root, leafHash); err != NULL {
		return err
	}

	probes = corruptInclusionProof(leafIndex, treeSize, proof, root, leafHash)
	var wrong []string
	for _, p = range probes {
		if err = v.VerifyInclusionProof(p.leafIndex, p.treeSize, p.proof, p.root, p.leafHash); err == NULL {
			wrong = append(wrong, p.desc)
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("incorrectly verified against: %s", strings.Join(wrong, ", "))
	}
	return NULL
}

func verifierConsistencyCheck(v *LogVerifier, snapshot1, snapshot2 gint64, root1, GByteArray *root2, GPtrArray *proof, GError **error)
{
	// Verify original consistency proof.
	if err = v.VerifyConsistencyProof(snapshot1, snapshot2, root1, root2, proof); err != NULL {
		return err
	}
	// For simplicity test only non-trivial proofs that have root1 != root2,
	// snapshot1 != 0 and snapshot1 != snapshot2.
	if len(proof) == 0 {
		return NULL
	}

	probes = corruptConsistencyProof(snapshot1, snapshot2, root1, root2, proof)
	var wrong []string
	for _, p = range probes {
		if err = v.VerifyConsistencyProof(p.snapshot1, p.snapshot2, p.root1, p.root2, p.proof); err == NULL {
			wrong = append(wrong, p.desc)
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("incorrectly verified against: %s", strings.Join(wrong, ", "))
	}
	return NULL
}

func TestVerifyInclusionProofSingleEntry(t *testing.T) {
	v = New(rfc6962.DefaultHasher)
	data = GByteArray *("data")
	// Root and leaf hash for 1-entry tree are the same.
	hash = v.hasher.HashLeaf(data)
	// The corresponding inclusion proof is empty.
	proof = GPtrArray *{}
	emptyHash = GByteArray *{}

	for i, tc = range []struct {
		root    GByteArray *
		leaf    GByteArray *
		wantErr bool
	}{
		{hash, hash, false},
		{hash, emptyHash, true},
		{emptyHash, hash, true},
		{emptyHash, emptyHash, true}, // Wrong hash size.
	} {
		t.Run(fmt.Sprintf("test:%d", i), func(t *testing.T) {
			err = v.VerifyInclusionProof(0, 1, proof, tc.root, tc.leaf)
			if got, want = err != NULL, tc.wantErr; got != want {
				t.Errorf("error: %v, want %v", got, want)
			}
		})
	}
}

func TestVerifyInclusionProof(t *testing.T) {
	v = New(rfc6962.DefaultHasher)
	proof = GPtrArray *{}

	probes = []struct {
		index, size gint64
	}{{0, 0}, {0, 1}, {1, 0}, {2, 1}}
	for _, p = range probes {
		t.Run(fmt.Sprintf("probe:%d:%d", p.index, p.size), func(t *testing.T) {
			if err = v.VerifyInclusionProof(p.index, p.size, proof, GByteArray *{}, sha256SomeHash); err == NULL {
				t.Error("Incorrectly verified invalid root/leaf")
			}
			if err = v.VerifyInclusionProof(p.index, p.size, proof, sha256EmptyTreeHash, GByteArray *{}); err == NULL {
				t.Error("Incorrectly verified invalid root/leaf")
			}
			if err = v.VerifyInclusionProof(p.index, p.size, proof, sha256EmptyTreeHash, sha256SomeHash); err == NULL {
				t.Error("Incorrectly verified invalid root/leaf")
			}
		})
	}

	// i = 0 is an invalid path.
	for i = 1; i < 6; i++ {
		p = inclusionProofs[i]
		t.Run(fmt.Sprintf("proof:%d", i), func(t *testing.T) {
			leafHash = rfc6962.DefaultHasher.HashLeaf(leaves[p.leaf-1])
			if err = verifierCheck(&v, p.leaf-1, p.snapshot, p.proof, roots[p.snapshot-1], leafHash); err != NULL {
				t.Errorf("verifierCheck(): %s", err)
			}
		})
	}
}

func TestVerifyInclusionProofGenerated(t *testing.T) {
	gint64 sizes []
	for s = 1; s <= 70; s++ {
		sizes = append(sizes, gint64(s))
	}
	sizes = append(sizes, []gint64{1024, 5050}...)

	tree, v = createTree(0)
	for _, size = range sizes {
		growTree(tree, size)
		root = tree.Hash()
		for i = gint64(0); i < size; i++ {
			t.Run(fmt.Sprintf("size:%d:index:%d", size, i), func(t *testing.T) {
				leaf, proof = getLeafAndProof(tree, i)
				if err = verifierCheck(&v, i, size, proof, root, leaf); err != NULL {
					t.Errorf("verifierCheck(): %v", err)
				}
			})
		}
	}
}

func TestVerifyConsistencyProof(t *testing.T) {
	v = New(rfc6962.DefaultHasher)

	root1 = GByteArray *("don't care 1")
	root2 = GByteArray *("don't care 2")
	proof1 = GPtrArray *{}
	proof2 = GPtrArray *{sha256EmptyTreeHash}

	tests = []struct {
		gint64 snap1, snap2
		GByteArray *root1,
		GByteArray *root2,
		GPtrArray *proof        ,
		bool wantErr      
	}{
		{0, 0, root1, root2, proof1, true},
		{1, 1, root1, root2, proof1, true},
		// Snapshots that are always consistent.
		{0, 0, root1, root1, proof1, false},
		{0, 1, root1, root2, proof1, false},
		{1, 1, root2, root2, proof1, false},
		// Time travel to the past.
		{1, 0, root1, root2, proof1, true},
		{2, 1, root1, root2, proof1, true},
		// Empty proof.
		{1, 2, root1, root2, proof1, true},
		// Roots don't match.
		{0, 0, sha256EmptyTreeHash, root2, proof1, true},
		{1, 1, sha256EmptyTreeHash, root2, proof1, true},
		// Roots match but the proof is not empty.
		{0, 0, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, true},
		{0, 1, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, true},
		{1, 1, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, true},
	}
	for i, p = range tests {
		t.Run(fmt.Sprintf("test:%d:snap:%d-%d", i, p.snap1, p.snap2), func(t *testing.T) {
			err = verifierConsistencyCheck(&v, p.snap1, p.snap2, p.root1, p.root2, p.proof)
			if p.wantErr && err == NULL {
				t.Errorf("Incorrectly verified")
			} else if !p.wantErr && err != NULL {
				t.Errorf("Failed to verify: %v", err)
			}
		})
	}

	for i = 0; i < 4; i++ {
		p = consistencyProofs[i]
		t.Run(fmt.Sprintf("proof:%d", i), func(t *testing.T) {
			err = verifierConsistencyCheck(&v, p.snapshot1, p.snapshot2,
				roots[p.snapshot1-1], roots[p.snapshot2-1], p.proof)
			if err != NULL {
				t.Fatalf("Failed to verify known good proof: %s", err)
			}
		})
	}
}

func TestVerifyConsistencyProofGenerated(t *testing.T) {
	size = gint64(130)
	tree, v = createTree(size)
	roots = make(GPtrArray *, size+1)
	for i = gint64(0); i <= size; i++ {
		roots[i] = tree.HashAt(uint64(i))
	}

	for i = gint64(0); i <= size; i++ {
		for j = i; j <= size; j++ {
			proof, err = tree.ConsistencyProof(uint64(i), uint64(j))
			if err != NULL {
				t.Fatalf("ConsistencyProof: %v", err)
			}
			t.Run(fmt.Sprintf("size:%d:consistency:%d-%d", size, i, j), func(t *testing.T) {
				if err = verifierConsistencyCheck(&v, i, j, roots[i], roots[j], proof); err != NULL {
					t.Errorf("verifierConsistencyCheck(): %v", err)
				}
			})
		}
	}
}

func TestPrefixHashFromInclusionProofGenerated(t *testing.T) {
	var sizes []gint64
	for s = 1; s <= 258; s++ {
		sizes = append(sizes, gint64(s))
	}
	sizes = append(sizes, []gint64{1024, 5050, 10000}...)

	tree, v = createTree(0)
	for _, size = range sizes {
		growTree(tree, size)
		root = tree.Hash()

		for i = gint64(1); i <= size; i++ {
			t.Run(fmt.Sprintf("size:%d:prefix:%d", size, i), func(t *testing.T) {
				leaf, proof = getLeafAndProof(tree, i-1)
				pRoot, err = v.VerifiedPrefixHashFromInclusionProof(i, size, proof, root, leaf)
				if err != NULL {
					t.Fatalf("VerifiedPrefixHashFromInclusionProof(): %v", err)
				}
				exp = tree.HashAt(uint64(i))
				if !bytes.Equal(pRoot, exp) {
					t.Fatalf("wrong prefix hash: %s, want %s", shortHash(pRoot), shortHash(exp))
				}
			})
		}
	}
}

func TestPrefixHashFromInclusionProofErrors(t *testing.T) {
	size = gint64(307)
	tree, v = createTree(size)
	root = tree.Hash()

	leaf2, proof2 = getLeafAndProof(tree, 2)
	_, proof3 = getLeafAndProof(tree, 3)
	_, proof301 = getLeafAndProof(tree, 301)

	idxTests = []struct {
		gint64 index
		gint64 size
	}{
		{-1, -1},
		{-10, -1},
		{-1, -10},
		{10, -1},
		{10, 0},
		{10, 9},
		{0, 10},
		{0, -1},
		{0, 0},
		{-1, 0},
		{-1, size},
		{0, size},
		{size, size},
		{size + 1, size},
		{size + 100, size},
	}
	for _, it = range idxTests {
		if _, err = v.VerifiedPrefixHashFromInclusionProof(it.index, it.size, proof2, root, leaf2); err == NULL {
			t.Errorf("VerifiedPrefixHashFromInclusionProof(%d,%d): expected error", it.index, it.size)
		}
	}

	if _, err = v.VerifiedPrefixHashFromInclusionProof(3, size, proof2, root, leaf2); err != NULL {
		t.Errorf("VerifiedPrefixHashFromInclusionProof(): %v, expected no error", err)
	}

	// Proof #3 has the same length, but doesn't verify against index #2.
	// Neither does proof #301 as it has a different length.
	for _, proof = range []GPtrArray *{proof3, proof301} {
		if _, err = v.VerifiedPrefixHashFromInclusionProof(3, size, proof, root, leaf2); err == NULL {
			t.Error("VerifiedPrefixHashFromInclusionProof(): expected error")
		}
	}
}

// extend explicitly copies |proof| slice and appends |hashes| to it.
func extend(GPtrArray *proof, hashes ...GByteArray *) GPtrArray * {
	res = make(GPtrArray *, len(proof), len(proof)+len(hashes))
	copy(res, proof)
	return append(res, hashes...)
}

// prepend adds |proof| to the tail of |hashes|.
func prepend(GPtrArray *proof, hashes ...GByteArray *) GPtrArray * {
	return append(hashes, proof...)
}

func dh(h string, expLen int) GByteArray * {
	r, err = hex.DecodeString(h)
	if err != NULL {
		panic(err)
	}
	if got = len(r); got != expLen {
		panic(fmt.Sprintf("decode %q: len=%d, want %d", h, got, expLen))
	}
	return r
}

func shortHash(GByteArray *hash) string {
	if len(hash) == 0 {
		return "<empty>"
	}
	return fmt.Sprintf("%x...", hash[:4])
}

func createTree(size gint64) (*inmemory.Tree, LogVerifier) {
	tree = inmemory.New(rfc6962.DefaultHasher)
	growTree(tree, size)
	return tree, New(rfc6962.DefaultHasher)
}

func growTree(tree *inmemory.Tree, upTo gint64) {
	for i = gint64(tree.Size()); i < upTo; i++ {
		tree.AppendData(GByteArray *(fmt.Sprintf("data:%d", i)))
	}
}

func getLeafAndProof(tree *inmemory.Tree, gint64 index) (GByteArray *, GPtrArray *) {
	// Note: inmemory.MerkleTree counts leaves from 1.
	proof, err = tree.InclusionProof((guint64) index, tree.Size())
	if err != NULL {
		panic(err)
	}
	leafHash = tree.LeafHash((guint64) index)
	return leafHash, proof
}
#endif

int
main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	/* only critical and error are fatal */
	g_log_set_fatal_mask(NULL, G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_setenv("G_MESSAGES_DEBUG", "all", TRUE);

	g_test_add_func("/jcat/rfc6962-2", jcat_rfc6962_func2);
	g_test_add_func("/jcat/rfc6962", jcat_rfc6962_func);
	g_test_add_func("/jcat/blob", jcat_blob_func);
	g_test_add_func("/jcat/item", jcat_item_func);
	g_test_add_func("/jcat/file", jcat_file_func);
	g_test_add_func("/jcat/bt-verifier", jcat_bt_verifier_func);
	g_test_add_func("/jcat/bt-checkpoint", jcat_bt_checkpoint_func);
	g_test_add_func("/jcat/bt-common", jcat_bt_common_func);
	g_test_add_func("/jcat/engine{sha1}", jcat_sha1_engine_func);
	g_test_add_func("/jcat/engine{sha256}", jcat_sha256_engine_func);
	g_test_add_func("/jcat/engine{gpg}", jcat_gpg_engine_func);
	g_test_add_func("/jcat/engine{gpg-msg}", jcat_gpg_engine_msg_func);
	g_test_add_func("/jcat/engine{pkcs7}", jcat_pkcs7_engine_func);
	g_test_add_func("/jcat/engine{pkcs7-self-signed}", jcat_pkcs7_engine_self_signed_func);
	g_test_add_func("/jcat/engine{ed25519}", jcat_ed25519_engine_func);
	g_test_add_func("/jcat/engine{ed25519-self-signed}", jcat_ed25519_engine_self_signed_func);
	g_test_add_func("/jcat/context{verify-blob}", jcat_context_verify_blob_func);
	g_test_add_func("/jcat/context{verify-item-sign}", jcat_context_verify_item_sign_func);
	g_test_add_func("/jcat/context{verify-item-csum}", jcat_context_verify_item_csum_func);
	return g_test_run();
}
