#pragma once

#include <glib-object.h>

GByteArray *
jcat_rfc6962_hash_leaf(GByteArray *buf);

GByteArray *
jcat_rfc6962_hash_children(GByteArray *lbuf, GByteArray *rbuf);

/*
 * Compute a subtree hash for a node on or below the tree's right border. Assumes `proof` hashes
 * are ordered from lower levels to upper, and `seed` is the initial subtree/leaf hash on the path
 * located at the specified `index` on its level.
 */
GByteArray *
jcat_hash_chain_inner(GByteArray *seed, GPtrArray *proof, gint64 index);

/*
 * Compute a subtree hash like jcat_hash_chain_inner, but only take hashes to the left from the path
 * into consideration, which effectively means the result is a hash of the corresponding earlier
 * version of this subtree.
 */
GByteArray *
jcat_hash_chain_inner_right(GByteArray *seed, GPtrArray *proof, gint64 index);

/*
 * Chains proof hashes along tree borders. This differs from inner chaining because `proof`
 * contains only left-side subtree hashes.
 */
GByteArray *
jcat_hash_chain_border_right(GByteArray *seed, GPtrArray *proof);

GByteArray *
jcat_bt_inclusion_proof_calculate_root(gint64 leafIndex,
				       gint64 treeSize,
				       GPtrArray *proof,
				       GByteArray *leafHash,
				       GError **error);

gboolean
jcat_bt_inclusion_proof_verify(gint64 leafIndex,
			       guint64 treeSize,
			       GPtrArray *proof,
			       GByteArray *root,
			       GByteArray *leafHash,
			       GError **error);

gboolean
jcat_bt_consistency_proof_verify(gint64 snapshot1,
				 gint64 snapshot2,
				 GByteArray *root1,
				 GByteArray *root2,
				 GPtrArray *proof,
				 GError **error);
