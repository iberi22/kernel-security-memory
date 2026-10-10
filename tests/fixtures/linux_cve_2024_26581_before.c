#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/netfilter/nf_tables.h>

static void nft_rbtree_gc_elem_remove(struct net *net, struct nft_set *set,
				       struct nft_rbtree *priv,
				       struct nft_rbtree_elem *rbe)
{
	lockdep_assert_held_write(&priv->lock);
	nft_setelem_data_deactivate(net, set, &rbe->priv);
	rb_erase(&rbe->node, &priv->root);
}

static const struct nft_rbtree_elem *
nft_rbtree_gc_elem(const struct nft_set *__set, struct nft_rbtree *priv,
		   struct nft_rbtree_elem *rbe, u8 genmask)
{
	struct nft_set *set = (struct nft_set *)__set;
	struct rb_node *prev = rb_prev(&rbe->node);
	struct net *net = read_pnet(&set->net);
	struct nft_rbtree_elem *rbe_prev;
	struct nft_trans_gc *gc;

	gc = nft_trans_gc_alloc(set, 0, GFP_ATOMIC);
	if (!gc)
		return ERR_PTR(-ENOMEM);

	/* search for end interval coming before this element.
	 * end intervals don't carry a timeout extension, they
	 * are coupled with the interval start element.
	 */
	while (prev) {
		rbe_prev = rb_entry(prev, struct nft_rbtree_elem, node);
		if (nft_rbtree_interval_end(rbe_prev) &&
		    nft_set_elem_active(&rbe_prev->ext, genmask))
			break;

		prev = rb_prev(prev);
	}

	rbe_prev = NULL;
	if (prev) {
		rbe_prev = rb_entry(prev, struct nft_rbtree_elem, node);
		nft_rbtree_gc_elem_remove(net, set, priv, rbe_prev);

		/* There is always room in this trans gc for this element,
		 * memory allocation never actually happens, hence, the warning
		 * splat in such case. No need to set NFT_SET_ELEM_DEAD_BIT,
		 * this is synchronous gc which never fails.
		 */
		gc = nft_trans_gc_queue_sync(gc, GFP_ATOMIC);
		if (WARN_ON_ONCE(!gc))
			return ERR_PTR(-ENOMEM);

		nft_trans_gc_elem_add(gc, rbe_prev);
	}

	nft_rbtree_gc_elem_remove(net, set, priv, rbe);
	gc = nft_trans_gc_queue_sync(gc, GFP_ATOMIC);
	if (WARN_ON_ONCE(!gc))
		return ERR_PTR(-ENOMEM);

	nft_trans_gc_elem_add(gc, rbe);

	nft_trans_gc_queue_sync_done(gc);

	return rbe_prev;
}

static bool nft_rbtree_update_first(const struct nft_set *set,
				    struct nft_rbtree_elem *rbe,
				    struct rb_node *first)
{
	struct nft_rbtree_elem *first_elem;

	first_elem = rb_entry(first, struct nft_rbtree_elem, node);
	if (nft_rbtree_cmp(set, rbe, first_elem) < 0)
		return true;

	return false;
}
