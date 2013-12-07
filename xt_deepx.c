#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netfilter/x_tables.h>
#include <linux/string.h>
#include <linux/textsearch.h>
#include "xt_deepx.h"

MODULE_AUTHOR("Nicolas Chaim");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Packet contect inspection match");
MODULE_ALIAS("ipt_deepx");
MODULE_ALIAS("ip6t_deepx");

bool pkt_match(char *str, int str_len, const struct sk_buff *skb, int pkt_ofst) {
	static const int blk_len = 32;
	char pktbuf[blk_len]; int i, rlen;
	if (pkt_ofst + str_len > skb->len) return false;
	for(i = 0; i < str_len; i+=blk_len){
		rlen = min(blk_len, str_len-i);
		if (skb_copy_bits(skb, pkt_ofst+i, pktbuf, rlen) < 0) BUG();
		if(strncmp(pktbuf, &str[i], rlen)) return false;
	}
	return true;
}

static bool deepx_mt(const struct sk_buff *skb, struct xt_action_param *par) {
	unsigned int i, reg_i = 0, res; char *pbuf;
	u_int32_t regs[10] = {}, acc = 0, pos = 0;
    xt_deepx_test ins; xt_deepx_info *di = (xt_deepx_info *) par->matchinfo;
    uint8_t nxt_grp = 0, grp_invert = 0;
    struct ts_state ts_st;

	#define rg(u) regs[(reg_i-(u)+10)%10]
	#define rg_psh(v) reg_i=(reg_i+1)%10,regs[reg_i]=(v)
	#define arg (ins.use_reg ? rg(ins.reg) : ins.ival)

	for(i = 0; i < di->n_tests; i++) {
		ins = di->tests[i];
		// printk("deepx test %u/%u: op=%s acc=%u pos=%u arg=%u pktlen=%u\n", i+1, di->n_tests, dbg_opname(ins.op), acc, pos, arg, skb->len);
		if (ins.op == XT_DEEPX_NEWGRP) {
			pos = 0; reg_i = 0; acc = 0;
			grp_invert = ins.grp_invert;
			nxt_grp = (ins.nxt_grp ? (i + ins.nxt_grp) : 0);
		} else if (ins.op == XT_DEEPX_SEARCH) {
			if (pos + ins.strlen > skb->len) return false;
			memset(&ts_st, 0, sizeof(struct ts_state));
			res = skb_find_text((struct sk_buff *)skb, pos, skb->len, di->istr_cfg[ins.strid], &ts_st);
			if (res == UINT_MAX) goto grp_brk;
			pos += res + ins.strlen;
		} else if (ins.op == XT_DEEPX_STRCMP) {
			if (!pkt_match(&di->sbuf[ins.strofst], ins.strlen, skb, pos)) goto grp_brk;
			pos += ins.strlen;
		} else if (ins.op == XT_DEEPX_READ) {
			acc = 0; if (pos + ins.rdlen > skb->len) goto grp_brk;
			pbuf = ((char *) &acc) + (ins.big_endian ? (4-ins.rdlen) : 0);
			if (skb_copy_bits(skb, pos, pbuf, ins.rdlen) < 0) BUG();
			if (ins.big_endian) acc = ntohl(acc);
			rg_psh(acc); pos += ins.rdlen;
		} else if (ins.op == XT_DEEPX_SAVEPOS) rg_psh(pos);
		else if (ins.op == XT_DEEPX_ARITH_END) rg_psh(acc);
		else if (ins.op == XT_DEEPX_SKIP) pos += arg;
		else if (ins.op == XT_DEEPX_ARITH_BEGIN) acc = arg;
		else if (ins.op == XT_DEEPX_ADD) acc += arg;
		else if (ins.op == XT_DEEPX_SUB) acc -= arg;
		else if (ins.op == XT_DEEPX_DIV) acc /= arg;
		else if (ins.op == XT_DEEPX_MUL) acc *= arg;
		else if (ins.op == XT_DEEPX_LSHIFT) acc <<= arg;
		else if (ins.op == XT_DEEPX_RSHIFT) acc >>= arg;
		else if (ins.op == XT_DEEPX_AND) acc &= arg;
		else if (ins.op == XT_DEEPX_TEST_EQ) { if (acc != arg) goto grp_brk; }
		else if (ins.op == XT_DEEPX_TEST_MIN) { if (acc < arg) goto grp_brk; }
		else if (ins.op == XT_DEEPX_TEST_MAX) { if (acc > arg) goto grp_brk; }
		continue;
grp_brk:
		if (grp_invert && (i = nxt_grp)) continue;
		return false;
	}
	return true;

	#undef rg
	#undef rg_psh
	#undef arg
}

static int deepx_mt_check(const struct xt_mtchk_param *par) {
	int i; xt_deepx_test ins; struct ts_config *cfg;
	xt_deepx_info *di = (xt_deepx_info *) par->matchinfo;
	for(i = 0; i < di->n_tests; i++) {
		ins = di->tests[i];
		if (ins.op == XT_DEEPX_SEARCH) {
			cfg = textsearch_prepare("kmp", &di->sbuf[ins.strofst], ins.strlen, GFP_KERNEL, TS_AUTOLOAD);
			if(IS_ERR(cfg)) return PTR_ERR(cfg);
			di->istr_cfg[ins.strid] = cfg;
		}
	}
	return 0;
}

static void deepx_mt_destroy(const struct xt_mtdtor_param *par) {
	int i; xt_deepx_info *di = (xt_deepx_info *) par->matchinfo;
	for(i = 0; i < di->n_istr; i++)
		textsearch_destroy(di->istr_cfg[i]);
}

static struct xt_match xt_deepx_mt_reg __read_mostly = {
	.name       = "deepx",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = deepx_mt,
	.matchsize  = sizeof(xt_deepx_info),
	.checkentry = deepx_mt_check,
	.destroy    = deepx_mt_destroy,
	.me         = THIS_MODULE,
};

static int __init deepx_mt_init(void) {
	return xt_register_match(&xt_deepx_mt_reg);
}

static void __exit deepx_mt_exit(void) {
	xt_unregister_match(&xt_deepx_mt_reg);
}

module_init(deepx_mt_init);
module_exit(deepx_mt_exit);
