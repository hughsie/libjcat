/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gio/gio.h>

#include "jcat-bt-proof-private.h"
#include "jcat-bt-proof.h"
#include "jcat-common-private.h"

#define RFC6962_LEAF_HASH_PREFIX 0x00
#define RFC6962_NODE_HASH_PREFIX 0x01

/**
 * jcat_rfc6962_hash_leaf:
 * @buf: (not nullable): the input buffer
 *
 * Hashes a leaf node according to RFC6962 (Section 2.1).
 *
 * Returns: (transfer full): the hash result
 *
 * Since: 0.2.2
 **/
GByteArray *
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

/**
 * jcat_rfc6962_hash_children:
 * @lbuf: the buffer for the left child
 * @rbuf: the buffer for the right child
 *
 * Hashes a node with two children according to RFC6962 (Section 2.1).
 *
 * Returns: (transfer full): the hash result
 *
 * Since: 0.2.2
 **/
GByteArray *
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

/**
 * jcat_bt_hash_chain_inner:
 * @seed: (not nullable): initial subtree/leaf hash
 * @proof: (not nullable) (element-type GByteArray): hashes in the proof ordered from lower to upper
 * @index: the location of @seed on its level
 *
 * Compute a subtree hash for a node on or below the tree's right border.
 *
 * Returns: (transfer full): the computed subtree hash
 *
 * Since: 0.2.2
 **/
GByteArray *
jcat_bt_hash_chain_inner(GByteArray *seed, GPtrArray *proof, gint64 index)
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
		jcat_set_byte_array(&subtree, subtree_tmp);
	}
	return g_steal_pointer(&subtree);
}

/**
 * jcat_bt_hash_chain_inner_right:
 * @seed: (not nullable): initial subtree/leaf hash
 * @proof: (not nullable) (element-type GByteArray): hashes in the proof
 * @index: the location of @seed on its level
 *
 * Compute a subtree hash like jcat_bt_hash_chain_inner, but only take hashes to the left from the
 * path into consideration, which effectively means the result is a hash of the corresponding
 * earlier version of this subtree.
 *
 * Returns: (transfer full): the computed subtree hash
 *
 * Since: 0.2.2
 **/
GByteArray *
jcat_bt_hash_chain_inner_right(GByteArray *seed, GPtrArray *proof, gint64 index)
{
	g_autoptr(GByteArray) subtree = g_byte_array_ref(seed);
	for (guint i = 0; i < proof->len; i++) {
		GByteArray *h = g_ptr_array_index(proof, i);
		if (((index >> i) & 1) == 1) {
			g_autoptr(GByteArray) subtree_tmp = jcat_rfc6962_hash_children(h, subtree);
			jcat_set_byte_array(&subtree, subtree_tmp);
		}
	}
	return g_steal_pointer(&subtree);
}

/**
 * jcat_bt_hash_chain_border_right:
 * @seed: (not nullable): initial subtree/leaf hash
 * @proof: (not nullable) (element-type GByteArray): hashes in the proof
 *
 * Chains proof hashes along tree borders. This differs from inner chaining because @proof
 * contains only left-side subtree hashes.
 *
 * Returns: (transfer full): the computed subtree hash
 *
 * Since: 0.2.2
 **/
GByteArray *
jcat_bt_hash_chain_border_right(GByteArray *seed, GPtrArray *proof)
{
	g_autoptr(GByteArray) subtree = g_byte_array_ref(seed);
	for (guint i = 0; i < proof->len; i++) {
		GByteArray *h = g_ptr_array_index(proof, i);
		g_autoptr(GByteArray) subtree_tmp = jcat_rfc6962_hash_children(h, subtree);
		jcat_set_byte_array(&subtree, subtree_tmp);
	}
	return g_steal_pointer(&subtree);
}

/*
 * This breaks down inclusion proof for a leaf at the specified |index| in a tree of the
 * specified |size| into 2 components.
 * The splitting point between them is where paths to leaves |index| and |size-1| diverge.
 * Returns lengths of the bottom and upper proof parts correspondingly. The sum
 * of the two determines the correct length of the inclusion proof.
 */
static void
jcat_decomp_inclusion_proof(guint64 index, guint64 size, guint *inner, guint *border)
{
	guint inner_tmp = jcat_inner_proof_size(index, size);
	if (inner != NULL)
		*inner = inner_tmp;
	if (border != NULL)
		*border = jcat_bits_ones_count64(index >> inner_tmp);
}

/**
 * jcat_bt_inclusion_proof_calculate_root:
 * @leaf_index: the index of the leaf
 * @tree_size: the number of nodes in the tree
 * @proof: (not nullable) (element-type GByteArray): neighbor nodes from the bottom to the root
 * @leaf_hash: (not nullable): the leaf hash
 * @error: (nullable): #GError, or %NULL
 *
 * This calculates the expected tree root given the proof and leaf.
 *
 * Returns: (transfer full): the root
 *
 * Since: 0.2.2
 **/
GByteArray *
jcat_bt_inclusion_proof_calculate_root(gint64 leaf_index,
				       gint64 tree_size,
				       GPtrArray *proof,
				       GByteArray *leaf_hash,
				       GError **error)
{
	guint inner = 0;
	guint border = 0;
	g_autoptr(GByteArray) res = NULL;
	g_autoptr(GPtrArray) proof_left = NULL;
	g_autoptr(GPtrArray) proof_right = NULL;

	if (leaf_index < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leaf_index %u < 0",
			    (guint)leaf_index);
		return NULL;
	}
	if (tree_size < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "tree_size %u < 0",
			    (guint)tree_size);
		return NULL;
	}
	if (leaf_index >= tree_size) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leaf_index is beyond tree_size: %u >= %u",
			    (guint)leaf_index,
			    (guint)tree_size);
		return NULL;
	}
	if (leaf_hash->len != 32) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leaf_hash has unexpected size %u, want 32",
			    leaf_hash->len);
		return FALSE;
	}

	jcat_decomp_inclusion_proof(leaf_index, tree_size, &inner, &border);
	if (proof->len != inner + border) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "wrong proof size %u, want %u",
			    (guint)proof->len,
			    (guint)inner + border);
		return NULL;
	}

	proof_left = jcat_byte_arrays_slice_left(proof, inner, error);
	if (proof_left == NULL)
		return NULL;
	proof_right = jcat_byte_arrays_slice_right(proof, inner, error);
	if (proof_right == NULL)
		return NULL;
	res = jcat_bt_hash_chain_inner(leaf_hash, proof_left, leaf_index);
	return jcat_bt_hash_chain_border_right(res, proof_right);
}

/**
 * jcat_bt_inclusion_proof_verify:
 * @leaf_index: the index of the leaf
 * @tree_size: the number of nodes in the tree
 * @proof: (not nullable) (element-type GByteArray): neighbor nodes from the bottom to the root
 * @leaf_hash: (not nullable): the leaf hash
 * @root: (not nullable): the root hash
 * @error: (nullable): #GError, or %NULL
 *
 * Verifies the correctness of the proof given the passed in information about the tree and leaf.
 *
 * Returns: %TRUE if success, %FALSE if not
 *
 * Since: 0.2.2
 **/
gboolean
jcat_bt_inclusion_proof_verify(gint64 leaf_index,
			       guint64 tree_size,
			       GPtrArray *proof,
			       GByteArray *root,
			       GByteArray *leaf_hash,
			       GError **error)
{
	g_autoptr(GByteArray) calc_root = NULL;

	calc_root =
	    jcat_bt_inclusion_proof_calculate_root(leaf_index, tree_size, proof, leaf_hash, error);
	if (calc_root == NULL)
		return FALSE;

	if (!jcat_byte_array_compare(calc_root, root, error)) {
		g_autofree gchar *str1 = jcat_hex_encode_string(calc_root);
		g_autofree gchar *str2 = jcat_hex_encode_string(root);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	/* success */
	return TRUE;
}

/**
 * jcat_bt_consistency_proof_verify:
 * @snapshot1: the first snapshot
 * @snapshot2: the second snapshot
 * @root1: (not nullable): the first root
 * @root2: (not nullable): the second root
 * @proof: (not nullable) (element-type GByteArray): the proof hashes
 * @error: (nullable): #GError, or %NULL
 *
 * Checks that the passed in consistency proof is valid between the passed in tree snapshots.
 * Snapshots are the respective tree sizes. Requires @shapshot2 >= @snapshot1 >= 0.
 *
 * Returns: %TRUE if success, %FALSE if not
 *
 * Since: 0.2.2
 **/
gboolean
jcat_bt_consistency_proof_verify(gint64 snapshot1,
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
	g_autoptr(GByteArray) hash1_tmp = NULL;
	g_autoptr(GByteArray) hash2_tmp = NULL;

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
		if (!jcat_byte_array_compare(root1, root2, error)) {
			g_autofree gchar *str1 = jcat_hex_encode_string(root1);
			g_autofree gchar *str2 = jcat_hex_encode_string(root2);
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

	jcat_decomp_inclusion_proof(snapshot1 - 1, snapshot2, &inner, &border);
	shift = jcat_bits_trailing_zeros64((guint64)snapshot1);
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
	proof_new = jcat_byte_arrays_slice_right(proof, start, error);
	if (proof_new == NULL)
		return FALSE;

	/*
	 * Now proof->len == inner+border, and proof is effectively a suffix of
	 * inclusion proof for entry |snapshot1-1| in a tree of size |snapshot2|
	 */

	/* verify the first root */
	//	ch = hashChainer(v)
	mask = (snapshot1 - 1) >> (guint)shift; /* start chaining from level |shift| */

	proof_left = jcat_byte_arrays_slice_left(proof_new, inner, error);
	if (proof_left == NULL)
		return FALSE;
	proof_right = jcat_byte_arrays_slice_right(proof_new, inner, error);
	if (proof_right == NULL)
		return FALSE;

	hash1_tmp = jcat_bt_hash_chain_inner_right(seed, proof_left, mask);
	hash1 = jcat_bt_hash_chain_border_right(hash1_tmp, proof_right);
	if (!jcat_byte_array_compare(hash1, root1, error)) {
		g_autofree gchar *str1 = jcat_hex_encode_string(hash1);
		g_autofree gchar *str2 = jcat_hex_encode_string(root1);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	/* verify the second root */
	hash2_tmp = jcat_bt_hash_chain_inner(seed, proof_left, mask);
	hash2 = jcat_bt_hash_chain_border_right(hash2_tmp, proof_right);
	if (!jcat_byte_array_compare(hash2, root2, error)) {
		g_autofree gchar *str1 = jcat_hex_encode_string(hash2);
		g_autofree gchar *str2 = jcat_hex_encode_string(root2);
		g_prefix_error(error, "CalculatedRoot=%s, ExpectedRoot=%s: ", str1, str2);
		return FALSE;
	}

	/* proof OK */
	return TRUE;
}
