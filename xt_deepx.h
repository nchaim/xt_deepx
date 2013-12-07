#ifndef XT_DEEPX_H_
#define XT_DEEPX_H_

enum xt_deepx_ops {
	XT_DEEPX_NEWGRP = 1,
	XT_DEEPX_SEARCH,
	XT_DEEPX_STRCMP,
	XT_DEEPX_READ,
	XT_DEEPX_SAVEPOS,
	XT_DEEPX_ARITH_END,
	XT_DEEPX_ARITH_BEGIN ,
	XT_DEEPX_SKIP,
	XT_DEEPX_ADD = '+',
	XT_DEEPX_SUB = '-',
	XT_DEEPX_DIV = '/',
	XT_DEEPX_MUL = '*',
	XT_DEEPX_LSHIFT = '<',
	XT_DEEPX_RSHIFT = '>',
	XT_DEEPX_AND = '&',
	XT_DEEPX_TEST_EQ,
	XT_DEEPX_TEST_MIN,
	XT_DEEPX_TEST_MAX
};

#define XT_DEEPX_SBUF_SZ 128
#define XT_DEEPX_MAX_ISTR 16
#define XT_DEEPX_MAX_TESTS 64

typedef struct xt_deepx_test_t {
	uint8_t op;
	union {
		struct {
			uint8_t use_reg;
			union {uint32_t ival; uint8_t reg;};
		};
		struct {uint8_t strofst, strlen, strid;};
		struct {uint8_t big_endian, rdlen;};
		struct {uint8_t grp_invert, nxt_grp;};
	};
} xt_deepx_test;

typedef struct xt_deepx_info_t {
	xt_deepx_test tests[XT_DEEPX_MAX_TESTS];
	uint8_t n_tests;
	char sbuf[XT_DEEPX_SBUF_SZ];
	uint8_t sbuf_i;
	struct ts_config __attribute__((aligned(8))) *istr_cfg[XT_DEEPX_MAX_ISTR];
	uint8_t n_istr;
} xt_deepx_info;


const char * dbg_opname(int op){
	#define n_(nm) if(op == nm) return #nm
	n_(XT_DEEPX_NEWGRP);    n_(XT_DEEPX_NEWGRP);      n_(XT_DEEPX_SEARCH);
	n_(XT_DEEPX_STRCMP);    n_(XT_DEEPX_READ);        n_(XT_DEEPX_SAVEPOS);
	n_(XT_DEEPX_ARITH_END); n_(XT_DEEPX_ARITH_BEGIN); n_(XT_DEEPX_SKIP);
	n_(XT_DEEPX_ADD);       n_(XT_DEEPX_SUB);         n_(XT_DEEPX_DIV);
	n_(XT_DEEPX_MUL);       n_(XT_DEEPX_LSHIFT);      n_(XT_DEEPX_RSHIFT);
	n_(XT_DEEPX_AND);       n_(XT_DEEPX_TEST_EQ);     n_(XT_DEEPX_TEST_MIN);
	n_(XT_DEEPX_TEST_MAX);
	return "<unknown>";
	#undef n_
}

#endif /* XT_DEEPX_H_ */
