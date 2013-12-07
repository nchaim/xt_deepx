#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <xtables.h>
#include "xt_deepx.h"

#define check(x) if (!(x)) xtables_error(PARAMETER_PROBLEM, "DEEPX parameter error")

enum {OPT_XRULE = 0};
static const struct xt_option_entry deepx_mt_opts[] = {
	{.name = "xrule", .id = OPT_XRULE, .type = XTTYPE_STRING, .flags = XTOPT_MAND | XTOPT_MULTI | XTOPT_INVERT},
	XTOPT_TABLEEND,
};

void save_bin_str(char *str, xt_deepx_info *di, xt_deepx_test *t) {
	int n, x, hex = 0, wc = 0; t->strofst = di->sbuf_i;
	while (*str && di->sbuf_i < XT_DEEPX_SBUF_SZ) {
	  if (*str == '|') {str++; hex ^= 1; wc = 0; continue;}
	  if (*str == '~') {str++; wc ^= 1; hex = 0; continue;}
	  if (hex && !sscanf(str, "%2x%n", &x, &n)) break;
	  di->sbuf[di->sbuf_i++] = hex ? (str+=n,x) : *str++;
	  if (wc) di->sbuf[di->sbuf_i++] = 0;
	}
	check(*str == 0);
	t->strlen = di->sbuf_i - t->strofst;
}

void add_test(xt_deepx_info *di, xt_deepx_test t){
	check (di->n_tests < XT_DEEPX_MAX_TESTS);
	di->tests[di->n_tests++] = t;
}

int parse_num(char *str, xt_deepx_test *t) {
	int64_t lval; char cval[2]; int n = 0;
	if (sscanf(str, "%li%n", &lval, &n)==1) {t->use_reg = 0; t->ival = (uint32_t) lval;}
	else if (sscanf(str, "%%%1[0-9]%n", cval, &n)==1) {t->use_reg = 1; t->reg = cval[0]-'0';}
	check(n); return n;
}

void parse_arith(char *str, xt_deepx_info *di){
	xt_deepx_test t = {.op = XT_DEEPX_ARITH_BEGIN};
	int n; char ns0[16], ns1[16];

	while(true) {
		str += parse_num(str, &t);
		add_test(di, t);
		if (sscanf(str, "%2[+-/*&<>]%n", ns0, &n) != 1 || n == 0) break; str +=n;
		t.op = ns0[0];
	}
	if (sscanf(str, "=%15[^]:]:%15[^]:]", ns0, ns1) == 2) {
		t.op = XT_DEEPX_TEST_MIN; parse_num(ns0, &t); add_test(di, t);
		t.op = XT_DEEPX_TEST_MAX; parse_num(ns1, &t); add_test(di, t);
	} else if (sscanf(str, "=%15[^]:]", ns0) == 1) {
		t.op = XT_DEEPX_TEST_EQ; parse_num(ns0, &t); add_test(di, t);
	}
	t.op = XT_DEEPX_ARITH_END; add_test(di, t);
}

void parse_rule(const char *str, xt_deepx_info *di, bool invert) {
	xt_deepx_test t; int n; uint8_t *prv_nxt_grp = NULL;
	char ns0[16], ns1[16], buf[128];

	t.op = XT_DEEPX_NEWGRP; t.grp_invert = invert; t.nxt_grp = 0; add_test(di, t);
	if (prv_nxt_grp) *prv_nxt_grp = di->n_tests-1;
	prv_nxt_grp = &(di->tests[di->n_tests-1].nxt_grp);

	while(*str) {
		n = 0; ns0[0] = 0; ns1[0] = 0;
		if (sscanf(str, "{%1[124]%2[BLEble]}%n", ns0, ns1, &n) >= 1) {
			t.big_endian = (*ns1=='B'||*ns1=='b');
			t.op = XT_DEEPX_READ; t.rdlen = *ns0-'0'; add_test(di, t);
		} else if (sscanf(str, "{#}%n", &n),n) {
			t.op = XT_DEEPX_SAVEPOS; add_test(di, t);
		} else if (sscanf(str, "<%15[^>]>%n", ns0, &n) == 1) {
			t.op = XT_DEEPX_SKIP; parse_num(ns0, &t); add_test(di, t);
		} else if (sscanf(str, "[%127[^]]]%n", buf, &n) == 1) {
			parse_arith(buf, di);
		} else if (sscanf(str, "*%127[^[{<*]%n", buf, &n) == 1) {
			t.op = XT_DEEPX_SEARCH; save_bin_str(buf, di, &t);
			check(di->n_istr < XT_DEEPX_MAX_ISTR);
			t.strid = di->n_istr++; add_test(di, t);
		} else if (sscanf(str, "%127[^[{<*]%n", buf, &n) == 1) {
			t.op = XT_DEEPX_STRCMP; save_bin_str(buf, di, &t); add_test(di, t);
		} else check(false);
		str += n;
	}
}

static void deepx_mt_check(struct xt_fcheck_call *cb) {
	int i; xt_deepx_test ins; xt_deepx_info *di = cb->data;

	check(di->n_tests > 0);
	check(di->n_tests <= XT_DEEPX_MAX_TESTS);
	for(i = 0; i < di->n_tests; i++) {
		ins = di->tests[i];
		switch(ins.op) {
		case XT_DEEPX_NEWGRP:
			check(ins.nxt_grp + i < di->n_tests); break;
		case XT_DEEPX_SEARCH:
			check(ins.strid < XT_DEEPX_MAX_ISTR);
			/* no break */
		case XT_DEEPX_STRCMP:
			check(ins.strlen > 0);
			check(ins.strofst+ins.strlen < XT_DEEPX_SBUF_SZ); break;
		case XT_DEEPX_READ:
			check(ins.rdlen == 1 || ins.rdlen == 2 || ins.rdlen == 4); break;
		}
	}
}

static void deepx_mt_help(void) {
	printf("deepx match options:\n[!] --xrule\n");
}

static void deepx_mt_parse(struct xt_option_call *cb) {
	xt_deepx_info *di = cb->data;
	xtables_option_parse(cb);

	if (cb->entry->id == OPT_XRULE)
		parse_rule(cb->arg, di, cb->invert);
}

static void deepx_mt_print(const void *ip, const struct xt_entry_match *match, int numeric) {
	xt_deepx_info *di = (void *) match->data;
	printf(" DEEPX match ilen=%u", (int) di->n_tests);
}

static struct xtables_match deepx_mt_reg = {
	.name          = "deepx",
	.family        = NFPROTO_UNSPEC,
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof(xt_deepx_info)),
	.userspacesize = offsetof(xt_deepx_info, istr_cfg),
	.help          = deepx_mt_help,
	.print         = deepx_mt_print,
	.x6_parse      = deepx_mt_parse,
	.x6_fcheck     = deepx_mt_check,
	.x6_options    = deepx_mt_opts,
};

void _init(void) {
	xtables_register_match(&deepx_mt_reg);
}
