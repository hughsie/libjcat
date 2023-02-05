#include "config.h"

#include <gio/gio.h>

#include "jcat-bt-proof-private.h"
#include "jcat-bt-proof.h"
#include "jcat-proof-bits-private.h"

#define RFC6962_LEAF_HASH_PREFIX 0x00
#define RFC6962_NODE_HASH_PREFIX 0x01

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

GByteArray *
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

GByteArray *
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

GByteArray *
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

/*
 * This calculates the expected tree root given the proof and leaf.
 * @leafIndex starts at 0. @treeSize is the number of nodes in the tree.
 * @proof is an array of neighbor nodes from the bottom to the root.
 */
GByteArray *
jcat_bt_inclusion_proof_calculate_root(gint64 leafIndex,
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
	if (leafHash->len != 32) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "leafHash has unexpected size %u, want 32",
			    leafHash->len);
		return FALSE;
	}

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
gboolean
jcat_bt_inclusion_proof_verify(gint64 leafIndex,
			       guint64 treeSize,
			       GPtrArray *proof,
			       GByteArray *root,
			       GByteArray *leafHash,
			       GError **error)
{
	g_autoptr(GByteArray) calcRoot = NULL;

	calcRoot =
	    jcat_bt_inclusion_proof_calculate_root(leafIndex, treeSize, proof, leafHash, error);
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
