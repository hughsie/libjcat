/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
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

/*
 * This breaks down inclusion proof for a leaf at the specified |index| in a tree of the
 * specified |size| into 2 components.
 * The splitting point between them is where paths to leaves |index| and |size-1| diverge.
 * Returns lengths of the bottom and upper proof parts correspondingly. The sum
 * of the two determines the correct length of the inclusion proof.
 */
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

	/* NULL check */
	if (bufsz1 > 0 && (buf1 == NULL || buf2 == NULL)) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "buf1 or buf2 NULL with non-zero size %" G_GSIZE_FORMAT
			    " %" G_GSIZE_FORMAT,
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

	/* sanity check; but note that pos == src->len is valid */
	if (pos > src->len) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "jcat_rfc6962_proof_slice_left: pos %u of %u",
			    pos,
			    src->len);
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

	/* sanity check; but note that pos == src->len is valid */
	if (pos > src->len) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "jcat_rfc6962_proof_slice_right: pos %u of %u",
			    pos,
			    src->len);
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

/*
 * This calculates the expected tree root given the proof and leaf.
 * @leafIndex starts at 0. @treeSize is the number of nodes in the tree.
 * @proof is an array of neighbor nodes from the bottom to the root.
 */
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
	// size %d, want %d", got, want); 		return FALSE;
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

/* verifies the correctness of the proof given the passed in information about the tree and leaf */
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

/*
 * Checks that the passed in consistency proof is valid between the passed in tree snapshots.
 * Snapshots are the respective tree sizes. Accepts @shapshot2 >= @snapshot1 >= 0.
 */
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
		/* proof OK */
		return TRUE;
	}

	if (snapshot1 == 0) {
		/* any snapshot greater than 0 is consistent with snapshot 0 */
		if (proof->len > 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "expected empty proof, but got %u components",
				    proof->len);
			return FALSE;
		}
		/* proof OK */
		return TRUE;
	}

	if (proof->len == 0) {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "empty proof");
		return FALSE;
	}

	decompInclProof(snapshot1 - 1, snapshot2, &inner, &border);
	shift = bits_TrailingZeros64((guint64)snapshot1);
	inner -= shift; /* note: shift < inner if snapshot1 < snapshot2 */

	/* proof includes the root hash for the sub-tree of size 2^shift */
	if (snapshot1 == 1 << ((guint)shift)) {
		/* unless snapshot1 is that very 2^shift */
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
	proof_new = jcat_rfc6962_proof_slice_right(proof, start, error);
	if (proof_new == NULL)
		return FALSE;

	/*
	 * Now proof->len == inner+border, and proof is effectively a suffix of
	 * inclusion proof for entry |snapshot1-1| in a tree of size |snapshot2|
	 */

	/* verify the first root */
	//	ch = hashChainer(v)
	mask = (snapshot1 - 1) >> (guint)shift; /* start chaining from level |shift| */

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

	/* verify the second root */
	hash2 = jcat_hash_chainInner(seed, proof_left, mask);
	hash2 = jcat_hash_chainBorderRight(hash2, proof_right);
	if (!fu_byte_array_compare(hash2, root2, error)) {
		g_autofree gchar *str1 = jcat_rfc6962_decode_string(hash2);
		g_autofree gchar *str2 = jcat_rfc6962_decode_string(root2);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	/* proof OK */
	return TRUE;
}

/*
 * Calculates a root hash over leaves [0..subSize), based on the inclusion |proof| and |leafHash|
 * for a leaf at index |subSize-1| in a tree of the specified |size| with the passed in @root hash.
 * Returns an error if the |proof| verification fails. The resulting smaller tree's root hash is
 * trusted iff the bigger tree's @root hash is trusted.
 */
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

typedef struct {
	gint64 leaf;
	gint64 snapshot;
	GPtrArray *proof;
} inclusionProofTestVector;

static inclusionProofTestVector *
inclusionProofTestVectorNew(void)
{
	inclusionProofTestVector *iptv = g_new0(inclusionProofTestVector, 1);
	iptv->proof = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	return iptv;
}

static void
inclusionProofTestVectorFree(inclusionProofTestVector *iptv)
{
	g_ptr_array_unref(iptv->proof);
}

static char
decode_nibble(char h)
{
	if (h >= '0' && h <= '9')
		return h - '0';
	if (h >= 'a' && h <= 'f')
		return h - 'a' + 10;
	if (h >= 'A' && h <= 'F')
		return h - 'A' + 10;
	return 0;
}

static GBytes *
dh(const char *s, int expected_size)
{
	gchar buf[32] = {};
	int input_size = strlen(s);
	g_assert_true(input_size <= 64 && input_size % 2 == 0);
	g_assert_cmpint(input_size, ==, expected_size * 2);
	for (int i = 0, j = 0; i < input_size; i += 2) {
		buf[j++] = (decode_nibble(s[i]) << 4) | decode_nibble(s[i + 1]);
	}
	return g_bytes_new(buf, input_size / 2);
}

static GBytes *
sha256SomeHash(void)
{
	return dh("abacaba000000000000000000000000000000000000000000060061e00123456", 32);
}

static GBytes *
sha256EmptyTreeHash(void)
{
	return dh("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
}

static GPtrArray *
inclusionProofs(void)
{
	GPtrArray *rv =
	    g_ptr_array_new_with_free_func((GDestroyNotify)inclusionProofTestVectorFree);
	inclusionProofTestVector *iptv = NULL;

	iptv = inclusionProofTestVectorNew();
	g_ptr_array_add(rv, iptv);

	iptv = inclusionProofTestVectorNew();
	iptv->leaf = 1;
	iptv->snapshot = 1;
	g_ptr_array_add(rv, iptv);

	iptv = inclusionProofTestVectorNew();
	iptv->leaf = 1;
	iptv->snapshot = 8;
	g_ptr_array_add(iptv->proof,
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32));
	g_ptr_array_add(iptv->proof,
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32));
	g_ptr_array_add(iptv->proof,
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32));
	g_ptr_array_add(rv, iptv);

	iptv = inclusionProofTestVectorNew();
	iptv->leaf = 6;
	iptv->snapshot = 8;
	g_ptr_array_add(iptv->proof,
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32));
	g_ptr_array_add(iptv->proof,
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32));
	g_ptr_array_add(iptv->proof,
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32));
	g_ptr_array_add(rv, iptv);

	iptv = inclusionProofTestVectorNew();
	iptv->leaf = 3;
	iptv->snapshot = 3;
	g_ptr_array_add(iptv->proof,
			dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32));
	g_ptr_array_add(rv, iptv);

	iptv = inclusionProofTestVectorNew();
	iptv->leaf = 2;
	iptv->snapshot = 5;
	g_ptr_array_add(iptv->proof,
			dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32));
	g_ptr_array_add(iptv->proof,
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32));
	g_ptr_array_add(iptv->proof,
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32));
	g_ptr_array_add(rv, iptv);

	return rv;
}

typedef struct {
	gint64 snapshot1;
	gint64 snapshot2;
	GPtrArray *proof;
} consistencyTestVector;

static consistencyTestVector *
consistencyTestVectorNew(void)
{
	consistencyTestVector *ctv = g_new0(consistencyTestVector, 1);
	ctv->proof = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	return ctv;
}

static void
consistencyTestVectorFree(consistencyTestVector *ctv)
{
	g_ptr_array_unref(ctv->proof);
	g_free(ctv);
}

static GPtrArray *
consistencyProofs(void)
{
	GPtrArray *rv = g_ptr_array_new_with_free_func((GDestroyNotify)consistencyTestVectorFree);
	consistencyTestVector *ctv = NULL;

	ctv = consistencyTestVectorNew();
	ctv->snapshot1 = 1;
	ctv->snapshot2 = 1;
	g_ptr_array_add(rv, ctv);

	ctv = consistencyTestVectorNew();
	ctv->snapshot1 = 1;
	ctv->snapshot2 = 8;
	g_ptr_array_add(ctv->proof,
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32));
	g_ptr_array_add(ctv->proof,
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32));
	g_ptr_array_add(ctv->proof,
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32));
	g_ptr_array_add(rv, ctv);

	ctv = consistencyTestVectorNew();
	ctv->snapshot1 = 6;
	ctv->snapshot2 = 8;
	g_ptr_array_add(ctv->proof,
			dh("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", 32));
	g_ptr_array_add(ctv->proof,
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32));
	g_ptr_array_add(ctv->proof,
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32));
	g_ptr_array_add(rv, ctv);

	ctv = consistencyTestVectorNew();
	ctv->snapshot1 = 2;
	ctv->snapshot2 = 5;
	g_ptr_array_add(ctv->proof,
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32));
	g_ptr_array_add(ctv->proof,
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32));
	g_ptr_array_add(rv, ctv);

	return rv;
}

static GPtrArray *
roots(void)
{
	GPtrArray *rv = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	g_ptr_array_add(rv,
			dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32));
	g_ptr_array_add(rv,
			dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32));
	g_ptr_array_add(rv,
			dh("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", 32));
	g_ptr_array_add(rv,
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32));
	g_ptr_array_add(rv,
			dh("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", 32));
	g_ptr_array_add(rv,
			dh("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", 32));
	g_ptr_array_add(rv,
			dh("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", 32));
	g_ptr_array_add(rv,
			dh("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", 32));
	return rv;
}

static GPtrArray *
leaves(void)
{
	GPtrArray *rv = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	g_ptr_array_add(rv, dh("", 0));
	g_ptr_array_add(rv, dh("00", 1));
	g_ptr_array_add(rv, dh("2021", 2));
	g_ptr_array_add(rv, dh("3031", 2));
	g_ptr_array_add(rv, dh("40414243", 4));
	g_ptr_array_add(rv, dh("5051525354555657", 8));
	g_ptr_array_add(rv, dh("606162636465666768696a6b6c6d6e6f", 16));
	return rv;
}

/* inclusionProbe is a parameter set for inclusion proof verification. */
typedef struct {
	gint64 leafIndex;
	gint64 treeSize;
	GByteArray *root;
	GByteArray *leafHash;
	GPtrArray *proof;

	/* A string literal for the description. Do not free. */
	const char *desc;
} inclusionProbe;

static inclusionProbe *
inclusionProbeNew(void)
{
	inclusionProbe *ip = g_new0(inclusionProbe, 1);
	return ip;
}

static void
inclusionProbeFree(inclusionProbe *ip)
{
	if (ip->root)
		g_byte_array_unref(ip->root);
	if (ip->leafHash)
		g_byte_array_unref(ip->leafHash);
	if (ip->proof)
		g_ptr_array_unref(ip->proof);
}

/* consistencyProbe is a parameter set for consistency proof verification. */
typedef struct {
	gint64 snapshot1;
	gint64 snapshot2;
	GByteArray *root1;
	GByteArray *root2;
	GPtrArray *proof;

	/* A string literal for the description. Do not free. */
	const char *desc;
} consistencyProbe;

static consistencyProbe *
consistencyProbeNew(void)
{
	consistencyProbe *cp = g_new0(consistencyProbe, 1);
	return cp;
}

static void
consistencyProbeFree(consistencyProbe *cp)
{
	if (cp->root1)
		g_byte_array_unref(cp->root1);
	if (cp->root2)
		g_byte_array_unref(cp->root2);
	if (cp->proof)
		g_ptr_array_unref(cp->proof);
}

static GPtrArray *
corruptInclusionProof(gint64 leafIndex,
		      gint64 treeSize,
		      GPtrArray *proof,
		      GByteArray *root,
		      GByteArray *leafHash)
{
	GPtrArray *ret = g_ptr_array_new_with_free_func((GDestroyNotify)inclusionProbeFree);
	inclusionProbe *ip = NULL;
	guint ln = proof->len;

	/* wrong leaf index */
	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex - 1;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "leafIndex - 1";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex + 1;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "leafIndex + 1";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex ^ 2;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "leafIndex ^ 2";
	g_ptr_array_add(ret, ip);

	/* wrong tree height */
	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize * 2;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "treeSize * 2";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize / 2;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "treeSize / 2";
	g_ptr_array_add(ret, ip);

	/* wrong leaf or root */
	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	{
		GByteArray *bad = g_byte_array_new();
		const unsigned char wrong_leaf[] = "WrongLeaf";
		ip->leafHash = g_byte_array_append(bad, wrong_leaf, sizeof wrong_leaf - 1);
	}
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "wrong leaf";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_bytes_unref_to_array(sha256EmptyTreeHash());
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "empty root";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_bytes_unref_to_array(sha256SomeHash());
	ip->leafHash = g_byte_array_ref(leafHash);
	ip->proof = g_ptr_array_ref(proof);
	ip->desc = "random root";
	g_ptr_array_add(ret, ip);

	/* add garbage at the end */
	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	{
		GPtrArray *new_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_add(new_proof, dh("", 0));
		ip->proof = new_proof;
	}
	ip->desc = "trailing garbage";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	{
		GPtrArray *new_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		GByteArray *extra_root = g_byte_array_ref(root);
		g_ptr_array_add(new_proof, g_byte_array_free_to_bytes(extra_root));
		ip->proof = new_proof;
	}
	ip->desc = "trailing root";
	g_ptr_array_add(ret, ip);

	/* add garbage at the front */
	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	{
		GPtrArray *new_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_insert(new_proof, 0, dh("", 0));
		ip->proof = new_proof;
	}
	ip->desc = "preceding garbage";
	g_ptr_array_add(ret, ip);

	ip = inclusionProbeNew();
	ip->leafIndex = leafIndex;
	ip->treeSize = treeSize;
	ip->root = g_byte_array_ref(root);
	ip->leafHash = g_byte_array_ref(leafHash);
	{
		GPtrArray *new_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		GByteArray *extra_root = g_byte_array_ref(root);
		g_ptr_array_insert(new_proof, 0, g_byte_array_free_to_bytes(extra_root));
		ip->proof = new_proof;
	}
	ip->desc = "preceding root";
	g_ptr_array_add(ret, ip);

	/* Modify single bit in an element of the proof. */
	for (guint i = 0; i < ln; ++i) {
		/* Copy the proof */
		GPtrArray *wrong_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		/* And also the data inside */
		GBytes *b = g_ptr_array_steal_index(wrong_proof, i);
		GByteArray *ba = g_bytes_unref_to_array(b);
		/* Flip the bit. */
		ba->data[i] ^= 8;
		b = g_byte_array_free_to_bytes(ba);
		g_ptr_array_insert(wrong_proof, i, b);

		ip = inclusionProbeNew();
		ip->leafIndex = leafIndex;
		ip->treeSize = treeSize;
		ip->root = g_byte_array_ref(root);
		ip->leafHash = g_byte_array_ref(leafHash);
		ip->proof = wrong_proof;
		ip->desc = "modified proof bit 3";
		g_ptr_array_add(ret, ip);
	}

	if (ln > 0) {
		GPtrArray *wrong_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_remove_index(wrong_proof, ln - 1);

		ip = inclusionProbeNew();
		ip->leafIndex = leafIndex;
		ip->treeSize = treeSize;
		ip->root = g_byte_array_ref(root);
		ip->leafHash = g_byte_array_ref(leafHash);
		ip->proof = wrong_proof;
		ip->desc = "removed component";
		g_ptr_array_add(ret, ip);
	}

	if (ln > 1) {
		GPtrArray *wrong_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_insert(wrong_proof, 1, g_bytes_ref(g_ptr_array_index(proof, 0)));

		ip = inclusionProbeNew();
		ip->leafIndex = leafIndex;
		ip->treeSize = treeSize;
		ip->root = g_byte_array_ref(root);
		ip->leafHash = g_byte_array_ref(leafHash);
		ip->proof = wrong_proof;
		ip->desc = "inserted component";
		g_ptr_array_add(ret, ip);
	}

	return ret;
}

static GPtrArray *
corruptConsistencyProof(gint64 snapshot1,
			gint64 snapshot2,
			GByteArray *root1,
			GByteArray *root2,
			GPtrArray *proof)
{
	GPtrArray *ret = g_ptr_array_new_with_free_func((GDestroyNotify)consistencyProbeFree);
	consistencyProbe *cp = NULL;
	guint ln = proof->len;

	GByteArray *bad_root = NULL;
	const unsigned char wrong_root[] = "WrongRoot";
	bad_root = g_byte_array_new();
	bad_root = g_byte_array_append(bad_root, wrong_root, sizeof wrong_root - 1);

	/* wrong snapshot index */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1 - 1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "snapshot1 - 1";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1 + 1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "snapshot1 + 1";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1 ^ 2;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "snapshot1 ^ 2";
	g_ptr_array_add(ret, cp);

	/* wrong tree height */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2 * 2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "snapshot2 * 2";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2 / 2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "snapshot2 / 2";
	g_ptr_array_add(ret, cp);

	/* wrong root */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(bad_root);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "wrong root 1";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(bad_root);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "wrong root 2";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root2);
	cp->root2 = g_byte_array_ref(root1);
	cp->proof = g_ptr_array_ref(proof);
	cp->desc = "swapped roots";
	g_ptr_array_add(ret, cp);

	/* empty proof */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	cp->proof = g_ptr_array_new();
	cp->desc = "empty proof";
	g_ptr_array_add(ret, cp);

	/* add garbage at the end */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_add(bad_proof, g_bytes_new(NULL, 0));
		cp->proof = bad_proof;
	}
	cp->desc = "trailing garbage";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_add(bad_proof, g_byte_array_ref(root1));
		cp->proof = bad_proof;
	}
	cp->desc = "trailing root1";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_add(bad_proof, g_byte_array_ref(root2));
		cp->proof = bad_proof;
	}
	cp->desc = "trailing root2";
	g_ptr_array_add(ret, cp);

	/* add garbage at the front */
	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_insert(bad_proof, 0, g_bytes_new(NULL, 0));
		cp->proof = bad_proof;
	}
	cp->desc = "preceding garbage";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_insert(bad_proof,
				   0,
				   g_byte_array_free_to_bytes(g_byte_array_ref(root1)));
		cp->proof = bad_proof;
	}
	cp->desc = "preceding root1";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_insert(bad_proof,
				   0,
				   g_byte_array_free_to_bytes(g_byte_array_ref(root2)));
		cp->proof = bad_proof;
	}
	cp->desc = "preceding root2";
	g_ptr_array_add(ret, cp);

	cp = consistencyProbeNew();
	cp->snapshot1 = snapshot1;
	cp->snapshot2 = snapshot2;
	cp->root1 = g_byte_array_ref(root1);
	cp->root2 = g_byte_array_ref(root2);
	{
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		GBytes *proof0 = g_ptr_array_index(proof, 0);
		g_ptr_array_insert(bad_proof, 0, g_bytes_ref(proof0));
		cp->proof = bad_proof;
	}
	cp->desc = "preceding proof[0]";
	g_ptr_array_add(ret, cp);

	if (ln > 0) {
		GPtrArray *bad_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		g_ptr_array_remove_index(bad_proof, ln - 1);

		cp = consistencyProbeNew();
		cp->snapshot1 = snapshot1;
		cp->snapshot2 = snapshot2;
		cp->root1 = g_byte_array_ref(root1);
		cp->root2 = g_byte_array_ref(root2);
		cp->proof = bad_proof;
		cp->desc = "truncated proof";
		g_ptr_array_add(ret, cp);
	}

	for (guint i = 0; i < ln; ++i) {
		/* copy the proof */
		GPtrArray *wrong_proof = g_ptr_array_copy(proof, (GCopyFunc)g_bytes_ref, NULL);
		/* and also the data inside */
		GBytes *b = g_ptr_array_steal_index(wrong_proof, i);
		GByteArray *ba = g_bytes_unref_to_array(b);
		/* flip the bit */
		ba->data[0] ^= 16;
		b = g_byte_array_free_to_bytes(ba);
		g_ptr_array_insert(wrong_proof, i, b);

		cp = consistencyProbeNew();
		cp->snapshot1 = snapshot1;
		cp->snapshot2 = snapshot2;
		cp->root1 = g_byte_array_ref(root1);
		cp->root2 = g_byte_array_ref(root2);
		cp->proof = wrong_proof;
		cp->desc = "modified proof[i] bit 4";
		g_ptr_array_add(ret, cp);
	}

	return ret;
}

static gboolean
verifierCheck(gint64 leafIndex,
	      gint64 treeSize,
	      GPtrArray *proof,
	      GByteArray *root,
	      GByteArray *leafHash,
	      GError **error)
{
	GByteArray *got = RootFromInclusionProof(leafIndex, treeSize, proof, leafHash, error);
	if (got == NULL)
		return FALSE;
	if (!fu_byte_array_compare(got, root, error)) {
		g_autofree gchar *str1 = jcat_rfc6962_decode_string(got);
		g_autofree gchar *str2 = jcat_rfc6962_decode_string(root);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}
	if (!VerifyInclusionProof(leafIndex, treeSize, proof, root, leafHash, error))
		return FALSE;

	{
		g_autoptr(GPtrArray) probes =
		    corruptInclusionProof(leafIndex, treeSize, proof, root, leafHash);
		guint wrong = 0;
		for (guint i = 0; i < probes->len; ++i) {
			inclusionProbe *p = g_ptr_array_index(probes, i);
			if (VerifyInclusionProof(p->leafIndex,
						 p->treeSize,
						 p->proof,
						 p->root,
						 p->leafHash,
						 error)) {
				if (wrong++ == 0) {
					g_set_error(error,
						    G_IO_ERROR,
						    G_IO_ERROR_FAILED,
						    "verifierCheck: incorrectly verified");
				}
				g_prefix_error(error, "case=%s ", p->desc);
			}
		}
	}
	// TODO: check if @error is set here
	return FALSE;
}

static gboolean
verifierConsistencyCheck(gint64 snapshot1,
			 gint64 snapshot2,
			 GByteArray *root1,
			 GByteArray *root2,
			 GPtrArray *proof,
			 GError **error)
{
	/* verify original consistency proof */
	if (!VerifyConsistencyProof(snapshot1, snapshot2, root1, root2, proof, error))
		return FALSE;

	/* For simplicity test only non-trivial proofs that have root1 != root2,
	 snapshot1 != 0 and snapshot1 != snapshot2.
	 */
	if (proof->len == 0)
		return TRUE;

	{
		g_autoptr(GPtrArray) probes =
		    corruptConsistencyProof(snapshot1, snapshot2, root1, root2, proof);
		guint wrong = 0;
		for (guint i = 0; i < probes->len; ++i) {
			consistencyProbe *p = g_ptr_array_index(probes, i);
			if (VerifyConsistencyProof(p->snapshot1,
						   p->snapshot2,
						   p->root1,
						   p->root2,
						   p->proof,
						   error)) {
				if (wrong++ == 0) {
					g_set_error(error,
						    G_IO_ERROR,
						    G_IO_ERROR_FAILED,
						    "incorrectly verified");
				}
				g_prefix_error(error, "case=%s ", p->desc);
			}
		}
	}
	// TODO: check if @error is set here
	return FALSE;
}

static void
TestVerifyInclusionProofSingleEntry(void)
{
	g_autoptr(GByteArray) data = g_byte_array_new();
	g_autoptr(GByteArray) hash = NULL;
	/* the corresponding inclusion proof is empty */
	g_autoptr(GPtrArray) proof = g_ptr_array_new();
	g_autoptr(GByteArray) emptyHash = g_byte_array_new();

	data = g_byte_array_append(data, (guint8 *)"data", 4);
	/* root and leaf hash for 1-entry tree are the same */
	hash = jcat_rfc6962_hash_leaf(data);

	{
		struct testcase {
			GByteArray *root;
			GByteArray *leaf;
			gboolean wantErr;
		};
		struct testcase testcases[] = {
		    {hash, hash, FALSE},
		    {hash, emptyHash, TRUE},
		    {emptyHash, hash, TRUE},
		    {emptyHash, emptyHash, TRUE}, /* wrong hash size */
		};

		for (guint i = 0, end = 4; i < end; i++) {
			g_autoptr(GError) error = NULL;
			gboolean ret = VerifyInclusionProof(0,
							    1,
							    proof,
							    testcases[i].root,
							    testcases[i].leaf,
							    &error);
			g_autofree gchar *str_root = jcat_rfc6962_decode_string(testcases[i].root);
			g_autofree gchar *str_leaf = jcat_rfc6962_decode_string(testcases[i].leaf);
			g_debug("ran test case %u (root=%s, leaf=%s) with ret %d",
				i,
				str_root,
				str_leaf,
				ret);
			if (testcases[i].wantErr) {
				g_assert_nonnull(error);
				g_assert_false(ret);
			} else {
				g_assert_no_error(error);
				g_assert_true(ret);
			}
		}
	}
}

static void
TestVerifyInclusionProof(void)
{
	g_autoptr(GPtrArray) ips = inclusionProofs();
	g_autoptr(GPtrArray) ls = leaves();
	g_autoptr(GPtrArray) rs = roots();
	g_autoptr(GPtrArray) proof = g_ptr_array_new();

	struct probe {
		gint64 index, size;
	};
	struct probe probes[] = {{0, 0}, {0, 1}, {1, 0}, {2, 1}};

	for (guint i = 0; i < 4; ++i) {
		g_autoptr(GByteArray) empty = g_byte_array_new();
		g_autoptr(GByteArray) someHash = g_bytes_unref_to_array(sha256SomeHash());
		g_autoptr(GByteArray) emptyTreeHash = g_bytes_unref_to_array(sha256EmptyTreeHash());
		g_autoptr(GError) error = NULL;
		gboolean ret;

		ret = VerifyInclusionProof(probes[i].index,
					   probes[i].size,
					   proof,
					   empty,
					   someHash,
					   &error);
		g_assert_false(ret);
		g_assert_nonnull(error);
		g_clear_error(&error);

		ret = VerifyInclusionProof(probes[i].index,
					   probes[i].size,
					   proof,
					   emptyTreeHash,
					   empty,
					   &error);
		g_assert_false(ret);
		g_assert_nonnull(error);
		g_clear_error(&error);

		ret = VerifyInclusionProof(probes[i].index,
					   probes[i].size,
					   proof,
					   emptyTreeHash,
					   someHash,
					   &error);
		g_assert_false(ret);
		g_assert_nonnull(error);
		g_clear_error(&error);
	}

	/* i = 0 is an invalid path */
	for (guint i = 1; i < 6; ++i) {
		inclusionProofTestVector *p = g_ptr_array_index(ips, i);
		GBytes *leaf = g_bytes_ref(g_ptr_array_index(ls, p->leaf - 1));
		g_autoptr(GByteArray) leafHash =
		    jcat_rfc6962_hash_leaf(g_bytes_unref_to_array(leaf));
		GBytes *root = g_bytes_ref(g_ptr_array_index(rs, p->snapshot - 1));

		g_autoptr(GError) error = NULL;
		verifierCheck(p->leaf - 1,
			      p->snapshot,
			      p->proof,
			      g_bytes_unref_to_array(root),
			      leafHash,
			      &error);
		g_prefix_error(&error, "verifierCheck() i = %u ", i);
		g_assert_no_error(error);
	}
}

typedef struct {
	/* GPtrArray of GPtrArray of GByteArray */
	GPtrArray *tree;
	gint64 leavesProcessed;
	gint64 levelCount;
} inmemoryTree;

static inmemoryTree *
newInmemoryTree(void)
{
	inmemoryTree *tree = g_new0(inmemoryTree, 1);
	tree->tree = g_ptr_array_new_with_free_func((GDestroyNotify)g_ptr_array_unref);
	return tree;
}

static void
inmemoryTreeFree(inmemoryTree *tree)
{
	g_ptr_array_unref(tree->tree);
}

static gint64
inmemoryTreeNodeCount(inmemoryTree *tree, gint64 level)
{
	GPtrArray *this_level = NULL;
	if (tree->tree->len <= level) {
		abort();
	}
	this_level = g_ptr_array_index(tree->tree, level);
	return this_level->len;
}

static gint64
inmemoryTreeLeafCount(inmemoryTree *tree)
{
	if (tree->tree->len == 0)
		return 0;
	return inmemoryTreeNodeCount(tree, 0);
}

static void
inmemoryTreeAddLevel(inmemoryTree *tree)
{
	g_ptr_array_add(tree->tree,
			g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref));
}

static gboolean
isPowerOfTwoPlusOne(gint64 x)
{
	if (x == 0)
		return FALSE;
	if (x == 1)
		return TRUE;
	return ((x - 1) & (x - 2)) == 0;
}

static void
inmemoryTreeAddLeaf(inmemoryTree *tree, GByteArray *leaf_data)
{
	GByteArray *leaf_hash = jcat_rfc6962_hash_leaf(leaf_data);
	gsize lazy_level_count = tree->tree->len;
	GPtrArray *leaf_level = NULL;
	gint64 leaf_count = 0;
	if (lazy_level_count == 0) {
		inmemoryTreeAddLevel(tree);
		tree->leavesProcessed = 1;
	}
	leaf_level = g_ptr_array_index(tree->tree, 0);
	g_ptr_array_add(leaf_level, leaf_hash);
	leaf_count = inmemoryTreeLeafCount(tree);
	if (isPowerOfTwoPlusOne(leaf_count)) {
		tree->levelCount++;
	}
}

static GByteArray *
inmemoryTreeRoot(inmemoryTree *tree)
{
	GPtrArray *last_level = g_ptr_array_index(tree->tree, tree->tree->len - 1);
	if (last_level->len > 1)
		abort();
	return g_byte_array_ref(g_ptr_array_index(last_level, 0));
}

static GByteArray *
inmemoryTreeUpdateToSnapshot(inmemoryTree *tree, gint64 snapshot)
{
	if (snapshot == 0) {
		return g_bytes_unref_to_array(sha256EmptyTreeHash());
	}
	if (snapshot == 1) {
		GPtrArray *leaf_level = g_ptr_array_index(tree->tree, 0);
		return g_byte_array_ref(g_ptr_array_index(leaf_level, 0));
	}
	if (snapshot == tree->leavesProcessed) {
		return inmemoryTreeRoot(tree);
	}
	g_assert_cmpint(snapshot, <=, inmemoryTreeLeafCount(tree));
	g_assert_cmpint(snapshot, >, tree->leavesProcessed);

	for (gint64 level = 0, first_node = tree->leavesProcessed, last_node = snapshot - 1;
	     last_node != 0;
	     level++, first_node >>= 1, last_node >>= 1) {
		if (tree->tree->len <= level + 1) {
			inmemoryTreeAddLevel(tree);
		} else if (inmemoryTreeNodeCount(tree, level + 1) == (first_node >> 1) + 1) {
			GPtrArray *next_level = g_ptr_array_index(tree->tree, level + 1);
			g_ptr_array_remove_index(next_level, next_level->len - 1);
		}
		for (gint64 j = first_node & ~(gint64)1; j < last_node; j += 2) {
			g_ptr_array_add(
			    g_ptr_array_index(tree->tree, level + 1),
			    jcat_rfc6962_hash_children(
				g_ptr_array_index((GPtrArray *)g_ptr_array_index(tree->tree, level),
						  j),
				g_ptr_array_index((GPtrArray *)g_ptr_array_index(tree->tree, level),
						  j + 1)));
		}
		if ((last_node & 1) == 0) {
			g_ptr_array_add(g_ptr_array_index(tree->tree, level + 1),
					g_byte_array_ref(g_ptr_array_index(
					    (GPtrArray *)g_ptr_array_index(tree->tree, level),
					    last_node)));
		}
	}
	tree->leavesProcessed = snapshot;
	return inmemoryTreeRoot(tree);
}

static GByteArray *
inmemoryTreeRecomputePastSnapshot(inmemoryTree *tree,
				  gint64 snapshot,
				  gint64 node_level,
				  GByteArray **node)
{
	gint64 level = 0;
	gint64 last_node = snapshot - 1;
	g_autoptr(GByteArray) subtree_root = NULL;
	if (snapshot == tree->leavesProcessed) {
		if (node != NULL && tree->tree->len > node_level) {
			GPtrArray *this_level = g_ptr_array_index(tree->tree, node_level);
			if (*node != NULL)
				g_byte_array_unref(*node);
			if (node_level > 0) {
				*node = g_byte_array_ref(
				    g_ptr_array_index(this_level, this_level->len - 1));
			} else {
				*node = g_byte_array_ref(g_ptr_array_index(this_level, last_node));
			}
		}
		return inmemoryTreeRoot(tree);
	}

	g_assert_cmpint(snapshot, <, tree->leavesProcessed);

	while ((last_node & 1) == 1) {
		if (node != NULL && node_level == level) {
			GPtrArray *this_level = g_ptr_array_index(tree->tree, level);
			if (*node != NULL)
				g_byte_array_unref(*node);
			*node = g_byte_array_ref(g_ptr_array_index(this_level, last_node));
		}
		last_node >>= 1;
		level++;
	}

	subtree_root = g_byte_array_ref(
	    g_ptr_array_index((GPtrArray *)g_ptr_array_index(tree->tree, level), last_node));

	if (node != NULL && node_level == level) {
		if (*node != NULL)
			g_byte_array_unref(*node);
		*node = g_byte_array_ref(subtree_root);
	}

	while (last_node != 0) {
		if ((last_node & 1) == 1) {
			GPtrArray *this_level = g_ptr_array_index(tree->tree, level);
			GByteArray *new_subtree_root =
			    jcat_rfc6962_hash_children(g_ptr_array_index(this_level, last_node - 1),
						       subtree_root);
			g_byte_array_unref(subtree_root);
			subtree_root = new_subtree_root;
		}

		last_node >>= 1;
		level++;
		if (node != NULL && node_level == level) {
			if (*node != NULL)
				g_byte_array_unref(*node);
			*node = g_byte_array_ref(subtree_root);
		}
	}
	return subtree_root;
}

static GByteArray *
inmemoryTreeRootAtSnapshot(inmemoryTree *tree, gint64 snapshot)
{
	if (snapshot == 0)
		return g_bytes_unref_to_array(sha256EmptyTreeHash());

	if (snapshot > inmemoryTreeLeafCount(tree))
		return NULL;

	if (snapshot >= tree->leavesProcessed)
		return inmemoryTreeUpdateToSnapshot(tree, snapshot);

	return inmemoryTreeRecomputePastSnapshot(tree, snapshot, 0, NULL);
}

static GByteArray *
inmemoryTreeCurrentRoot(inmemoryTree *tree)
{
	return inmemoryTreeRootAtSnapshot(tree, inmemoryTreeLeafCount(tree));
}

static GPtrArray *
inmemoryTreePathFromNodeToRootAtSnapshot(inmemoryTree *tree,
					 gint64 node,
					 gint64 level,
					 gint64 snapshot)
{
	GPtrArray *path = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	gint64 last_node = (snapshot - 1) >> level;
	if (snapshot == 0 || level >= tree->levelCount || node > last_node ||
	    snapshot > inmemoryTreeLeafCount(tree))
		return path;
	if (snapshot > tree->leavesProcessed)
		inmemoryTreeUpdateToSnapshot(tree, snapshot);

	while (last_node != 0) {
		gint64 sibling = (node & 1) == 1 ? node - 1 : node + 1;
		if (sibling < last_node) {
			g_ptr_array_add(path,
					g_byte_array_ref(g_ptr_array_index(
					    (GPtrArray *)g_ptr_array_index(tree->tree, level),
					    sibling)));
		} else if (sibling == last_node) {
			GByteArray *recomputed = NULL;
			inmemoryTreeRecomputePastSnapshot(tree, snapshot, level, &recomputed);
			g_assert_nonnull(recomputed);
			g_ptr_array_add(path, recomputed);
		}
		node >>= 1;
		last_node >>= 1;
		level++;
	}
	return path;
}

static GPtrArray *
inmemoryTreePathToRootAtSnapshot(inmemoryTree *tree, gint64 leaf, gint64 snapshot)
{
	if (leaf > snapshot || snapshot > inmemoryTreeLeafCount(tree) || leaf == 0)
		return g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);

	return inmemoryTreePathFromNodeToRootAtSnapshot(tree, leaf - 1, 0, snapshot);
}

static GPtrArray *
inmemoryTreePathToCurrentRoot(inmemoryTree *tree, gint64 leaf)
{
	return inmemoryTreePathToRootAtSnapshot(tree, leaf, inmemoryTreeLeafCount(tree));
}

static GPtrArray *
inmemoryTreeSnapshotConsistency(inmemoryTree *tree, gint64 snapshot1, gint64 snapshot2)
{
	GPtrArray *proof = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	gint64 level = 0;
	gint64 node = snapshot1 - 1;

	if (snapshot1 == 0 || snapshot1 >= snapshot2 || snapshot2 > inmemoryTreeLeafCount(tree)) {
		return proof;
	}

	while ((node & 1) == 1) {
		node >>= 1;
		level++;
	}

	if (snapshot2 > tree->leavesProcessed) {
		inmemoryTreeUpdateToSnapshot(tree, snapshot2);
	}

	if (node != 0) {
		g_ptr_array_add(proof,
				g_byte_array_ref(g_ptr_array_index(
				    (GPtrArray *)g_ptr_array_index(tree->tree, level),
				    node)));
	}

	g_ptr_array_extend_and_steal(
	    proof,
	    inmemoryTreePathFromNodeToRootAtSnapshot(tree, node, level, snapshot2));
	return proof;
}

static void
growTree(inmemoryTree *tree, gint64 upTo)
{
	for (gint64 i = inmemoryTreeLeafCount(tree); i < upTo; ++i) {
		g_autoptr(GString) str = g_string_new(NULL);
		g_autoptr(GByteArray) leaf = g_byte_array_new();
		g_autoptr(GByteArray) leaf_hash = NULL;
		g_string_printf(str, "data:%ld", i);
		g_byte_array_append(leaf, (const guint8 *)str->str, str->len);
		inmemoryTreeAddLeaf(tree, leaf);
	}
}

static inmemoryTree *
createTree(gint64 size)
{
	inmemoryTree *tree = newInmemoryTree();
	growTree(tree, size);
	return tree;
}

static void
getLeafAndProof(inmemoryTree *tree, gint64 index, GByteArray **leaf_hash, GPtrArray **proof)
{
	g_assert_nonnull(leaf_hash);
	g_assert_nonnull(proof);
	*proof = inmemoryTreePathToCurrentRoot(tree, index + 1);
	*leaf_hash = g_byte_array_ref(
	    g_ptr_array_index((GPtrArray *)g_ptr_array_index(tree->tree, 0), index));
}

static void
TestVerifyInclusionProofGenerated(void)
{
	inmemoryTree *tree = createTree(0);
	g_autoptr(GArray) sizes = g_array_new(FALSE, TRUE, sizeof(guint64));
	guint64 s;
	for (s = 1; s <= 70; ++s)
		g_array_append_val(sizes, s);

	s = 1024;
	g_array_append_val(sizes, s);
	s = 5050;
	g_array_append_val(sizes, s);

	for (gsize k = 0; k < sizes->len; ++k) {
		guint64 size = g_array_index(sizes, guint64, k);
		g_autoptr(GByteArray) root = NULL;
		growTree(tree, size);
		root = inmemoryTreeCurrentRoot(tree);
		for (guint64 i = 0; i < size; ++i) {
			g_autoptr(GByteArray) leaf_hash = NULL;
			g_autoptr(GPtrArray) proof = NULL;
			g_autoptr(GError) error = NULL;
			getLeafAndProof(tree, i, &leaf_hash, &proof);
			verifierCheck(i, size, proof, root, leaf_hash, &error);
			g_prefix_error(&error, "verifierCheck() i = %lu size = %lu ", i, size);
			g_assert_no_error(error);
		}
	}
	inmemoryTreeFree(tree);
}

static void
TestVerifyConsistencyProof(void)
{
	static const char root1_str[] = "don't care 1";
	static const char root2_str[] = "don't care 2";

	g_autoptr(GByteArray) root1 = g_byte_array_new();
	g_autoptr(GByteArray) root2 = g_byte_array_new();
	g_autoptr(GPtrArray) proof1 = g_ptr_array_new();
	g_autoptr(GPtrArray) proof2 =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	g_autoptr(GByteArray) emptyTreeRoot = g_bytes_unref_to_array(sha256EmptyTreeHash());

	g_autoptr(GPtrArray) rs = roots();
	g_autoptr(GPtrArray) cps = consistencyProofs();

	g_byte_array_append(root1, (const guint8 *)root1_str, strlen(root1_str));
	g_byte_array_append(root2, (const guint8 *)root2_str, strlen(root2_str));

	g_ptr_array_add(proof2, g_bytes_unref_to_array(sha256EmptyTreeHash()));

	{
		struct testcase {
			gint64 snap1, snap2;
			GByteArray *root1;
			GByteArray *root2;
			GPtrArray *proof;
			gboolean wantErr;
		};
		struct testcase testcases[] = {
		    {0, 0, root1, root2, proof1, TRUE},
		    {1, 1, root1, root2, proof1, TRUE},
		    /* snapshots that are always consistent */
		    {0, 0, root1, root1, proof1, FALSE},
		    {0, 1, root1, root2, proof1, FALSE},
		    {1, 1, root2, root2, proof1, FALSE},
		    /* time travel to the past */
		    {1, 0, root1, root2, proof1, TRUE},
		    {2, 1, root1, root2, proof1, TRUE},
		    /* empty proof */
		    {1, 2, root1, root2, proof1, TRUE},
		    /* roots don't match */
		    {0, 0, emptyTreeRoot, root2, proof1, TRUE},
		    {1, 1, emptyTreeRoot, root2, proof1, TRUE},
		    /* roots match but the proof is not empty */
		    {0, 0, emptyTreeRoot, emptyTreeRoot, proof2, TRUE},
		    {0, 1, emptyTreeRoot, emptyTreeRoot, proof2, TRUE},
		    {1, 1, emptyTreeRoot, emptyTreeRoot, proof2, TRUE},
		};
		for (int i = 0, end = sizeof testcases / sizeof(struct testcase); i < end; ++i) {
			g_autoptr(GError) error = NULL;
			gboolean ret = verifierConsistencyCheck(testcases[i].snap1,
								testcases[i].snap2,
								testcases[i].root1,
								testcases[i].root2,
								testcases[i].proof,
								&error);
			if (testcases[i].wantErr) {
				g_assert_nonnull(error);
				g_assert_false(ret);
			} else {
				g_prefix_error(&error, "verifierConsistencyCheck case i %d ", i);
				g_assert_no_error(error);
				g_assert_true(ret);
			}
		}
	}

	for (int i = 0; i < 4; ++i) {
		g_autoptr(GError) error = NULL;
		consistencyTestVector *p = g_ptr_array_index(cps, i);
		gboolean ret = verifierConsistencyCheck(p->snapshot1,
							p->snapshot2,
							g_ptr_array_index(rs, p->snapshot1 - 1),
							g_ptr_array_index(rs, p->snapshot2 - 1),
							p->proof,
							&error);
		g_prefix_error(&error, "Failed to verify known good proof: ");
		g_assert_no_error(error);
		g_assert_true(ret);
	}
}

static void
TestVerifyConsistencyProofGenerated(void)
{
	gint64 size = 130;
	inmemoryTree *tree = createTree(size);
	g_autoptr(GPtrArray) roots =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	for (gint64 i = 0; i <= size; ++i) {
		g_ptr_array_add(roots, inmemoryTreeRootAtSnapshot(tree, i));
	}
	for (gint64 i = 0; i <= size; ++i) {
		for (gint64 j = i; j <= size; ++j) {
			g_autoptr(GPtrArray) proof = inmemoryTreeSnapshotConsistency(tree, i, j);
			GError *error = NULL;
			gboolean ret = verifierConsistencyCheck(i,
								j,
								g_ptr_array_index(roots, i),
								g_ptr_array_index(roots, j),
								proof,
								&error);
			g_prefix_error(&error,
				       "failed to verify known good generated consistency proof at "
				       "size %ld consistency %ld %ld ",
				       size,
				       i,
				       j);
			g_assert_no_error(error);
			g_assert_true(ret);
		}
	}

	inmemoryTreeFree(tree);
}

static void
TestPrefixHashFromInclusionProofGenerated(void)
{
	inmemoryTree *tree = createTree(0);
	g_autoptr(GArray) sizes = g_array_new(FALSE, TRUE, sizeof(guint64));
	guint64 s;
	for (s = 1; s <= 258; ++s)
		g_array_append_val(sizes, s);

	s = 1024;
	g_array_append_val(sizes, s);
	s = 5050;
	g_array_append_val(sizes, s);
	s = 10000;
	g_array_append_val(sizes, s);

	for (gsize k = 0; k < sizes->len; ++k) {
		guint64 size = g_array_index(sizes, guint64, k);
		g_autoptr(GByteArray) root = NULL;
		growTree(tree, size);
		root = inmemoryTreeCurrentRoot(tree);
		for (gint64 i = 1; i <= (gint64)size; ++i) {
			g_autoptr(GByteArray) leaf_hash = NULL;
			g_autoptr(GPtrArray) proof = NULL;
			g_autoptr(GError) error = NULL;
			g_autoptr(GByteArray) pRoot = NULL;
			g_autoptr(GByteArray) exp = NULL;
			getLeafAndProof(tree, i - 1, &leaf_hash, &proof);
			pRoot = VerifiedPrefixHashFromInclusionProof(i,
								     size,
								     proof,
								     root,
								     leaf_hash,
								     &error);
			g_prefix_error(&error,
				       "VerifiedPrefixHashFromInclusionProof size %lu prefix %ld ",
				       size,
				       i);
			g_assert_no_error(error);
			exp = inmemoryTreeRootAtSnapshot(tree, i);
			if (!fu_byte_array_compare(pRoot, exp, &error)) {
				g_autofree gchar *str1 = jcat_rfc6962_decode_string(pRoot);
				g_autofree gchar *str2 = jcat_rfc6962_decode_string(exp);
				g_prefix_error(&error,
					       "Wrong prefix hash: got %s, want %s: ",
					       str1,
					       str2);
				g_assert_no_error(error);
			}
		}
	}

	inmemoryTreeFree(tree);
}

static void
TestPrefixHashFromInclusionProofErrors(void)
{
	gint64 size = 307;
	inmemoryTree *tree = createTree(size);
	g_autoptr(GByteArray) root = NULL;

	g_autoptr(GByteArray) leaf2 = NULL;
	g_autoptr(GPtrArray) proof2 = NULL;
	g_autoptr(GByteArray) leaf3 = NULL;
	g_autoptr(GPtrArray) proof3 = NULL;
	g_autoptr(GByteArray) leaf301 = NULL;
	g_autoptr(GPtrArray) proof301 = NULL;
	g_autoptr(GError) error = NULL;

	struct idxTest {
		gint64 index;
		gint64 size;
	};
	struct idxTest idxTests[] = {
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
	};

	root = inmemoryTreeCurrentRoot(tree);
	getLeafAndProof(tree, 2, &leaf2, &proof2);
	getLeafAndProof(tree, 3, &leaf3, &proof3);
	getLeafAndProof(tree, 301, &leaf301, &proof301);

	for (int i = 0, end = sizeof idxTests / sizeof(struct idxTest); i < end; ++i) {
		VerifiedPrefixHashFromInclusionProof(idxTests[i].index,
						     idxTests[i].size,
						     proof2,
						     root,
						     leaf2,
						     &error);
		g_assert_nonnull(error);
		g_clear_error(&error);
	}

	VerifiedPrefixHashFromInclusionProof(3, size, proof2, root, leaf2, &error);
	g_assert_no_error(error);

	/* Proof #3 has the same length, but doesn't verify against index #2.
	 Neither does proof #301 as it has a different length.*/
	VerifiedPrefixHashFromInclusionProof(3, size, proof3, root, leaf2, &error);
	g_assert_nonnull(error);
	g_clear_error(&error);
	VerifiedPrefixHashFromInclusionProof(3, size, proof301, root, leaf2, &error);
	g_assert_nonnull(error);
	g_clear_error(&error);

	inmemoryTreeFree(tree);
}

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

	g_test_add_func("/jcat/TestVerifyInclusionProofSingleEntry",
			TestVerifyInclusionProofSingleEntry);
	g_test_add_func("/jcat/TestVerifyInclusionProof", TestVerifyInclusionProof);
	g_test_add_func("/jcat/TestVerifyInclusionProofGenerated",
			TestVerifyInclusionProofGenerated);
	g_test_add_func("/jcat/TestVerifyConsistencyProof", TestVerifyConsistencyProof);
	g_test_add_func("/jcat/TestVerifyConsistencyProofGenerated",
			TestVerifyConsistencyProofGenerated);
	g_test_add_func("/jcat/TestPrefixHashFromInclusionProofGenerated",
			TestPrefixHashFromInclusionProofGenerated);
	g_test_add_func("/jcat/TestPrefixHashFromInclusionProofErrors",
			TestPrefixHashFromInclusionProofErrors);
	return g_test_run();
}
