/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Joe Qian <joeqian@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

GByteArray *
jcat_rfc6962_hash_leaf(GByteArray *buf);

GByteArray *
jcat_rfc6962_hash_children(GByteArray *lbuf, GByteArray *rbuf);

GByteArray *
jcat_bt_hash_chain_inner(GByteArray *seed, GPtrArray *proof, gint64 index);

GByteArray *
jcat_bt_hash_chain_inner_right(GByteArray *seed, GPtrArray *proof, gint64 index);

GByteArray *
jcat_bt_hash_chain_border_right(GByteArray *seed, GPtrArray *proof);

GByteArray *
jcat_bt_inclusion_proof_calculate_root(gint64 leaf_index,
				       gint64 tree_size,
				       GPtrArray *proof,
				       GByteArray *leaf_hash,
				       GError **error);

gboolean
jcat_bt_inclusion_proof_verify(gint64 leaf_index,
			       guint64 tree_size,
			       GPtrArray *proof,
			       GByteArray *root,
			       GByteArray *leaf_hash,
			       GError **error);

gboolean
jcat_bt_consistency_proof_verify(gint64 snapshot1,
				 gint64 snapshot2,
				 GByteArray *root1,
				 GByteArray *root2,
				 GPtrArray *proof,
				 GError **error);
