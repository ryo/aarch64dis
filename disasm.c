/*	$NetBSD$	*/

/*
 * Copyright (c) 2018 Ryo Shimizu <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef _KERNEL

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bitops.h>

#include <arch/aarch64/aarch64/disasm.h>

#else /* _KERNEL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/bitops.h>
#include <machine/int_fmtio.h>

#include "disasm.h"

#endif /* _KERNEL */


#define PRINTF		di->di_printf
#define PRINTADDR	di->di_printaddr

#define OPFUNC_DECL(func, a, b, c, d, e, f, g, h)		\
func(const disasm_interface_t *di, uint64_t pc, uint32_t insn,	\
    uint64_t a, uint64_t b, uint64_t c, uint64_t d,		\
    uint64_t e, uint64_t f, uint64_t g, uint64_t h)

#define UNUSED0	arg0 __unused
#define UNUSED1	arg1 __unused
#define UNUSED2	arg2 __unused
#define UNUSED3	arg3 __unused
#define UNUSED4	arg4 __unused
#define UNUSED5	arg5 __unused
#define UNUSED6	arg6 __unused
#define UNUSED7	arg7 __unused

#define OP0FUNC(func)						\
	static void						\
	OPFUNC_DECL(func,					\
	    UNUSED0, UNUSED1, UNUSED2, UNUSED3,			\
	    UNUSED4, UNUSED5, UNUSED6, UNUSED7)
#define OP1FUNC(func, a)					\
	static void						\
	OPFUNC_DECL(func, a,					\
	    UNUSED1, UNUSED2, UNUSED3, UNUSED4,			\
	    UNUSED5, UNUSED6, UNUSED7)
#define OP2FUNC(func, a, b)					\
	static void						\
	OPFUNC_DECL(func, a, b,					\
	    UNUSED2, UNUSED3, UNUSED4, UNUSED5,			\
	    UNUSED6, UNUSED7)
#define OP3FUNC(func, a, b, c)					\
	static void						\
	OPFUNC_DECL(func, a, b, c,				\
	    UNUSED3, UNUSED4, UNUSED5, UNUSED6,			\
	    UNUSED7)
#define OP4FUNC(func, a, b, c, d)				\
	static void						\
	OPFUNC_DECL(func, a, b, c, d,				\
	    UNUSED4, UNUSED5, UNUSED6, UNUSED7)
#define OP5FUNC(func, a, b, c, d, e)				\
	static void						\
	OPFUNC_DECL(  func, a, b, c, d, e,			\
	    UNUSED5, UNUSED6, UNUSED7)
#define OP6FUNC(func, a, b, c, d, e, f)				\
	static void						\
	OPFUNC_DECL(func, a, b, c, d, e, f,			\
	    UNUSED6, UNUSED7)
#define OP7FUNC(func, a, b, c, d, e, f, g)			\
	static void						\
	OPFUNC_DECL(func, a, b, c, d, e, f, g,			\
	    UNUSED7)
#define OP8FUNC(func, a, b, c, d, e, f, g, h)			\
	static void						\
	OPFUNC_DECL(func, a, b, c, d, e, f, g, h)

static const char *z_wxregs[2][32] = {
	{
		 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
		 "w8",  "w9", "w10", "w11", "w12", "w13", "w14", "w15",
		"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
		"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"
	},
	{
		 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		 "x8",  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"
	}
};

static const char *s_wxregs[2][32] = {
	{
		 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
		 "w8",  "w9", "w10", "w11", "w12", "w13", "w14", "w15",
		"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
		"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp"
	},
	{
		 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		 "x8",  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30",  "sp"
	}
};
#define ZREGNAME(s, n)	(z_wxregs[(s) & 1][(n) & 31])
#define SREGNAME(s, n)	(s_wxregs[(s) & 1][(n) & 31])

static const char *simdregs[5][32] = {
	{
		 "b0",  "b1",  "b2",  "b3",  "b4",  "b5",  "b6",  "b7",
		 "b8",  "b9", "b10", "b11", "b12", "b13", "b14", "b15",
		"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
		"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31"
	},
	{
		 "h0",  "h1",  "h2",  "h3",  "h4",  "h5",  "h6",  "h7",
		 "h8",  "h9", "h10", "h11", "h12", "h13", "h14", "h15",
		"h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
		"h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31"
	},
	{
		 "s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
		 "s8",  "s9", "s10", "s11", "s12", "s13", "s14", "s15",
		"s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
		"s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"
	},
	{
		 "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
		 "d8",  "d9", "d10", "d11", "d12", "d13", "d14", "d15",
		"d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
		"d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
	},
	{
		 "q0",  "q1",  "q2",  "q3",  "q4",  "q5",  "q6",  "q7",
		 "q8",  "q9", "q10", "q11", "q12", "q13", "q14", "q15",
		"q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
		"q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31"
	}
};
#define FREGNAME(s, n)	(simdregs[(s)][(n) & 31])

static const char *cregs[16] = {
	 "C0",  "C1",  "C2",  "C3",  "C4",  "C5",  "C6",  "C7",
	 "C8",  "C9", "C10", "C11", "C12", "C13", "C14", "C15"
};
#define CREGNAME(n)	cregs[(n) & 15]

static const char *conditioncode[16] = {
	"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt",
	"gt", "le", "al", "nv"
};
#define CONDNAME(c)	conditioncode[(c) & 15]
#define IVCONDNAME(c)	conditioncode[((c) ^ 1) & 15]

static const char *barrierop[16] = {
	 "#0", "oshld", "oshst", "osh",
	 "#4", "nshld", "nshst", "nsh",
	 "#8", "ishld", "ishst", "ish",
	"#12",    "ld",    "st",  "sy"
};
#define BARRIERNAME(op)	barrierop[(op) & 15]

static const char *prefetchop[32] = {
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
	"pldl3keep", "pldl3strm",        "#6",        "#7",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm",
	"plil3keep", "plil3strm",       "#14",       "#15",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
	"pstl3keep", "pstl3strm",       "#22",       "#23",
	      "#24",       "#25",       "#26",       "#27",
	      "#28",       "#29",       "#30",       "#31"
};
#define PREFETCHNAME(op)	prefetchop[(op) & 31]


#include "sysreg.h"

static const char *
sysregname_bsearch(uint32_t code)
{
	struct sysreg_table *base, *p;
	unsigned int lim;
	int32_t cmp;

	base = sysreg_table;
	for (lim = __arraycount(sysreg_table); lim != 0; lim >>= 1) {
		p = base + (lim >> 1);
		cmp = code - p->code;
		if (cmp == 0)
			return p->regname;
		if (cmp > 0) {
			base = p + 1;
			lim--;
		}
	}
	return NULL;
}

#define SYSREG_OP_READ	0x01
#define SYSREG_OP_WRITE	0x02

static const char *
sysregname(char *buf, size_t buflen, uint32_t rw,
    uint64_t op0, uint64_t op1, uint64_t CRn, uint64_t CRm, uint64_t op2)
{
	const char *name;
	uint32_t code;

	code = SYSREG_ENC(op0, op1, CRn, CRm, op2);

	/* special case for dbgdtrrx_el0(RO) and dbgdtrtx_el0(WO) */
	if (code == SYSREG_ENC(2,3,0,5,0)) {
		if (rw & SYSREG_OP_WRITE)
			return "dbgdtrtx_el0";
		return "dbgdtrrx_el0";
	}

	name = sysregname_bsearch(code);
	if (name == NULL) {
#define SYSREGNAMEBUFLEN	sizeof("s99_99_c99_c99_99")
		snprintf(buf, buflen, "s%u_%u_c%u_c%u_%u",
		    (u_int)op0, (u_int)op1, (u_int)CRn, (u_int)CRm, (u_int)op2);
		return buf;
	}
	return name;
}
#define RSYSREGNAME(buf, buflen, op0, op1, CRn, CRm, op2)		\
	sysregname(buf, buflen, SYSREG_OP_READ, op0, op1, CRn, CRm, op2)
#define WSYSREGNAME(buf, buflen, op0, op1, CRn, CRm, op2)		\
	sysregname(buf, buflen, SYSREG_OP_WRITE, op0, op1, CRn, CRm, op2)


static uint64_t
SignExtend(int bitwidth, uint64_t imm, unsigned int multiply)
{
	const uint64_t signbit = (1 << (bitwidth - 1));
	const uint64_t immmax = signbit << 1;

	if (imm & signbit)
		imm -= immmax;
	return imm * multiply;
}

static uint64_t
ZeroExtend(int bitwidth, uint64_t imm, unsigned int multiply)
{
	return imm * multiply;
}

/* rotate right. if n < 0, rotate left. */
static uint64_t
rotate(int bitwidth, uint64_t v, int n)
{
	uint64_t result;

	n &= (bitwidth - 1);
	result = (((v << (bitwidth - n)) | (v >> n)));
	if (bitwidth < 64)
		result &= ((1ULL << bitwidth) - 1);
	return result;
}

static bool
ValidBitMasks(uint64_t sf, uint64_t n, uint64_t imms, uint64_t immr)
{
	int esize, len;

	if ((sf == 0) && (n != 0))
		return false;

	len = fls64((n << 6) + (~imms & 0x3f)) - 1;
	if (len < 0)
		return false;

	esize = (1 << len);
	imms &= (esize - 1);
	if (imms == (uint64_t)(esize - 1))
		return false;

	return true;
}

static uint64_t
DecodeBitMasks(uint64_t sf, uint64_t n, uint64_t imms, uint64_t immr)
{
	const int bitwidth = (sf == 0) ? 32 : 64;
	uint64_t result;
	int esize, len;

	len = fls64((n << 6) + (~imms & 0x3f)) - 1;
	esize = (1 << len);
	imms &= (esize - 1);
	immr &= (esize - 1);
	result = rotate(esize, (1ULL << (imms + 1)) - 1, immr);
	while (esize < bitwidth) {
		result |= (result << esize);
		esize <<= 1;
	}
	if (sf == 0)
		result &= ((1ULL << bitwidth) - 1);
	return result;
}

static bool
MoveWidePreferred(uint64_t sf, uint64_t n, uint64_t imms, uint64_t immr)
{
#if 1
	uint64_t x = DecodeBitMasks(sf, n, imms, immr);

	if (sf == 0)
		x &= 0xffffffff;
	if (((x & 0xffffffffffff0000UL) == 0) ||
	    ((x & 0xffffffff0000ffffUL) == 0) ||
	    ((x & 0xffff0000ffffffffUL) == 0) ||
	    ((x & 0x0000ffffffffffffUL) == 0))
		return true;

	x = ~x;
	if (sf == 0)
		x &= 0xffffffff;
	if (((x & 0xffffffffffff0000UL) == 0) ||
	    ((x & 0xffffffff0000ffffUL) == 0) ||
	    ((x & 0xffff0000ffffffffUL) == 0) ||
	    ((x & 0x0000ffffffffffffUL) == 0))
		return true;

	return false;
#else
	const int bitwidth = (sf == 0) ? 32 : 64;

	if ((sf != 0) && (n == 0))
		return false;
	if ((sf == 0) && ((n != 0) || (immr > 0x1f)))
		return false;
	if (imms < 16)
		return ((-immr & 15) <= (15 - imms));
	if (imms >= (uint64_t)(bitwidth - 15))
		return ((immr & 15) <= (imms - (bitwidth - 15)));
	return false;
#endif
}

static bool
BFXPreferred(uint64_t sf, uint64_t opc, uint64_t imms, uint64_t immr)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	if (imms < immr)
		return false;
	if (imms == (bitwidth - 1))
		return false;
	if (immr == 0) {
		if ((sf == 0) && ((imms == 7) || (imms == 15)))
			return false;
		if ((sf != 0) && (opc == 0) &&
		    ((imms == 7) || (imms == 15) || (imms == 31)))
			return false;
	}

	return true;
}

#define SHIFTOP2(s, op1, op2)					\
	((const char *[]){ op1, op2 })[(s) & 1]
#define SHIFTOP4(s, op1, op2, op3, op4)				\
	((const char *[]){ op1, op2, op3, op4 })[(s) & 3]
#define SHIFTOP8(s, op1, op2, op3, op4, op5, op6, op7, op8)	\
	((const char *[]){ op1, op2, op3, op4, op5, op6, op7, op8 })[(s) & 7]

static const char *
DecodeShift(uint64_t shift)
{
	return SHIFTOP4(shift, "lsl", "lsr", "asr", "ror");
}

#define UNDEFINED(pc, insn, comment)	\
	PRINTF(".insn\t0x%08x\t# %s\n", insn, comment);

static void
extendreg_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t sf, uint64_t Rm, uint64_t option, uint64_t imm3,
    uint64_t Rn, uint64_t Rd,
    const char *op, const char *z_op)
{
	const int r = (sf == 0) ? 0 : ((option & 3) == 3) ? 1 : 0;

	if ((z_op != NULL) && (Rd == 31)) {
		PRINTF("%s\t", z_op);
	} else {
		PRINTF("%s\t%s, ", op, SREGNAME(sf, Rd));
	}

	PRINTF("%s, %s", SREGNAME(sf, Rn), ZREGNAME(r, Rm));

	if ((Rd == 31) || (Rn == 31)) {
		if (imm3 == 0) {
			if (!((sf == 0) && (option == 2)) &&
			    !((sf != 0) && (option == 3))) {
				PRINTF(", %s",
				    SHIFTOP8(option,
				    "uxtb", "uxth", "uxtw", "uxtx",
				    "sxtb", "sxth", "sxtw", "sxtx"));
			}
		} else {
			PRINTF(", %s #%u",
			    SHIFTOP8(option,
			    "uxtb", "uxth", "lsl", "lsl",
			    "sxtb", "sxth", "sxtw", "sxtx"),
			    (u_int)imm3);
		}
	} else {
		PRINTF(", %s",
		    SHIFTOP8(option,
		    "uxtb", "uxth", "uxtw", "uxtx",
		    "sxtb", "sxth", "sxtw", "sxtx"));
		if (imm3 != 0)
			PRINTF(" #%u", (u_int)imm3);
	}
	PRINTF("\n");
}

static void
shiftreg_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t sf, uint64_t shift, uint64_t Rm, uint64_t imm6,
    uint64_t Rn, uint64_t Rd,
    const char *dnm_op, const char *dzm_op, const char *znm_op)
{
	if ((sf == 0) && (imm6 >= 32)) {
		UNDEFINED(pc, insn, "illegal imm6");
		return;
	}

	if ((dzm_op != NULL) && (Rn == 31)) {
		PRINTF("%s\t%s, %s",
		    dzm_op,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else if ((znm_op != NULL) && (Rd == 31)) {
		PRINTF("%s\t%s, %s",
		    znm_op,
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%s\t%s, %s, %s",
		    dnm_op,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
	if (imm6 != 0)
		PRINTF(", %s #%u", DecodeShift(shift), (u_int)imm6);
	PRINTF("\n");
}

static inline int
regoffset_option_to_r(uint64_t option)
{
	switch (option) {
	case 2:
	case 6:
		return 0;
	case 3:
	case 7:
		return 1;
	default:
		return -1;
	}
}

static void
regoffset_b_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t Rm, uint64_t option, uint64_t shift, uint64_t Rn, uint64_t Rt,
    const char *op)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%d]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    0);
	}
}

static void
regoffset_h_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t Rm, uint64_t option, uint64_t shift, uint64_t Rn, uint64_t Rt,
    const char *op)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if ((shift == 0) && (option == 3)) {
		PRINTF("%s\t%s, [%s,%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm));
	} else if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s,%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%u]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    (u_int)shift);
	}
}

static void
regoffset_w_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t Rm, uint64_t option, uint64_t shift, uint64_t Rn, uint64_t Rt,
    const char *op)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if ((shift == 0) && (option == 3)) {
		PRINTF("%s\t%s, [%s,%s]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm));
	} else if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s,%s]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%u]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    (u_int)shift * 2);
	}
}

static void
regoffset_x_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t size, uint64_t Rm, uint64_t option, uint64_t shift,
    uint64_t Rn, uint64_t Rt,
    const char *op)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s%s]\n",
		    op,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		uint64_t amount = 2 + size;
		PRINTF("%s\t%s, [%s,%s,%s #%u]\n",
		    op,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    (u_int)amount);
	}
}

static void
addsub_imm_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t sf, uint64_t shift, uint64_t imm12, uint64_t Rn, uint64_t Rd,
    const char *op, const char *zop)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	if (Rd == 31) {
		PRINTF("%s\t%s, #0x%"PRIx64"%s\n",
		    zop,
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	} else {
		PRINTF("%s\t%s, %s, #0x%"PRIx64"%s\n",
		    op,
		    ZREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	}
}

static void
csetsel_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t sf, uint64_t Rm, uint64_t cond, uint64_t Rn, uint64_t Rd,
    const char *op, const char *op2, const char *op3)
{
	if ((Rn == Rm) && (Rn != 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%s\t%s, %s, %s\n",
		    op3,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCONDNAME(cond));
	} else if ((Rn == Rm) && (Rn == 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%s\t%s, %s\n",
		    op2,
		    ZREGNAME(sf, Rd),
		    IVCONDNAME(cond));
	} else {
		PRINTF("%s\t%s, %s, %s, %s\n",
		    op,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    CONDNAME(cond));
	}
}

OP0FUNC(op_undefined)
{
	UNDEFINED(pc, insn, "undefined");
}

OP4FUNC(op_adc, sf, Rm, Rn, Rd)
{
	PRINTF("adc\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP4FUNC(op_adcs, sf, Rm, Rn, Rd)
{
	PRINTF("adcs\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP6FUNC(op_add_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	extendreg_common(di, pc, insn, sf, Rm, option, imm3, Rn, Rd,
	    "add", NULL);
}

OP5FUNC(op_add_imm, sf, shift, imm12, Rn, Rd)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: mov_tofromsp */
	if ((Rd == 31 || Rn == 31) && (imm12 == 0)) {
		PRINTF("mov\t%s, %s\n",
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn));
	} else {
		PRINTF("add\t%s, %s, #0x%"PRIx64"%s\n",
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP2(shift, "", ", lsl #12"));
	}
}

OP6FUNC(op_add_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "add", NULL, NULL);
}

OP6FUNC(op_adds_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: cmn_extreg */
	extendreg_common(di, pc, insn, sf, Rm, option, imm3, Rn, Rd,
	    "adds", "cmn");
}

OP5FUNC(op_adds_imm, sf, shift, imm12, Rn, Rd)
{
	/* ALIAS: cmn_imm */
	addsub_imm_common(di, pc, insn, sf, shift, imm12, Rn, Rd,
	    "adds", "cmn");
}

OP6FUNC(op_adds_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}
	/* ALIAS: cmn_shiftreg */
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "adds", NULL, "cmn");
}

OP3FUNC(op_adr, immlo, immhi, Rd)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("adr\t%s, ", ZREGNAME(1, Rd));
	PRINTADDR(SignExtend(21, imm, 1) + pc);
	PRINTF("\n");
}

OP3FUNC(op_adrp, immlo, immhi, Rd)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("adrp\t%s, %"PRIx64"\n",
	    ZREGNAME(1, Rd),
	    SignExtend(21, imm, 4096) + (pc & -4096));
}

OP6FUNC(op_and_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("and\t%s, %s, #0x%"PRIx64"\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, imms, immr));
}

OP6FUNC(op_and_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "and", NULL, NULL);
}

OP6FUNC(op_ands_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	/* ALIAS: tst_imm */
	if (Rd == 31) {
		PRINTF("tst\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	} else {
		PRINTF("ands\t%s, %s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	}
}

OP6FUNC(op_ands_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: tst_shiftreg */
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "ands", NULL, "tst");
}

OP6FUNC(op_sbfm, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: asr_imm,sbfiz,sbfx,sxtb,sxth,sxtw */
	if ((imms != (bitwidth - 1)) && ((imms + 1) == immr)) {
		PRINTF("asr\t%s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    bitwidth - immr);
	} else if (imms == (bitwidth - 1)) {
		PRINTF("asr\t%s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr);
	} else if (imms < immr) {
		PRINTF("sbfiz\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else if (BFXPreferred(sf, 0, imms, immr)) {
		PRINTF("sbfx\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms - immr + 1) & (bitwidth - 1));
	} else if ((immr == 0) && (imms == 7)) {
		PRINTF("sxtb\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 15)) {
		PRINTF("sxth\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 31)) {
		PRINTF("sxtw\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else {
		UNDEFINED(pc, insn, "undefined");
	}
}

OP4FUNC(op_asr_reg, sf, Rm, Rn, Rd)
{
	/* ALIAS: asrv */
	/* "asr" always the preferred disassembly */
	PRINTF("asr\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

struct op_sys_table {
	uint32_t code;
	int flags;
#define OPE_NONE	0x00000000
#define OPE_XT		0x00000001
	const char *opname;
};

static struct op_sys_table op_sys_table[] = {
	{ SYSREG_ENC(1, 0, 7,  1, 0), OPE_NONE,	"ic\tialluis"		},
	{ SYSREG_ENC(1, 0, 7,  5, 0), OPE_NONE,	"ic\tiallu"		},
	{ SYSREG_ENC(1, 3, 7,  5, 1), OPE_XT,	"ic\tivau"		},
	{ SYSREG_ENC(1, 0, 7,  6, 1), OPE_XT,	"dc\tivac"		},
	{ SYSREG_ENC(1, 0, 7,  6, 2), OPE_XT,	"dc\tisw"		},
	{ SYSREG_ENC(1, 0, 7, 10, 2), OPE_XT,	"dc\tcsw"		},
	{ SYSREG_ENC(1, 0, 7, 14, 2), OPE_XT,	"dc\tcisw"		},
	{ SYSREG_ENC(1, 3, 7, 10, 1), OPE_XT,	"dc\tcvac"		},
	{ SYSREG_ENC(1, 3, 7, 11, 1), OPE_XT,	"dc\tcvau"		},
	{ SYSREG_ENC(1, 3, 7, 14, 1), OPE_XT,	"dc\tcivac"		},
	{ SYSREG_ENC(1, 3, 7,  4, 1), OPE_XT,	"dc\tzva"		},
	{ SYSREG_ENC(1, 0, 7,  8, 0), OPE_XT,	"at\ts1e1r"		},
	{ SYSREG_ENC(1, 0, 7,  8, 1), OPE_XT,	"at\ts1e1w"		},
	{ SYSREG_ENC(1, 0, 7,  8, 2), OPE_XT,	"at\ts1e0r"		},
	{ SYSREG_ENC(1, 0, 7,  8, 3), OPE_XT,	"at\ts1e0w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 0), OPE_XT,	"at\ts1e2r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 1), OPE_XT,	"at\ts1e2w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 4), OPE_XT,	"at\ts12e1r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 5), OPE_XT,	"at\ts12e1w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 6), OPE_XT,	"at\ts12e0r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 7), OPE_XT,	"at\ts12e0w"		},
	{ SYSREG_ENC(1, 6, 7,  8, 0), OPE_XT,	"at\ts1e3r"		},
	{ SYSREG_ENC(1, 6, 7,  8, 1), OPE_XT,	"at\ts1e3w"		},
	{ SYSREG_ENC(1, 0, 8,  3, 0), OPE_NONE,	"tlbi\tvmalle1is"	},
	{ SYSREG_ENC(1, 0, 8,  3, 1), OPE_XT,	"tlbi\tvae1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 2), OPE_XT,	"tlbi\taside1is"	},
	{ SYSREG_ENC(1, 0, 8,  3, 3), OPE_XT,	"tlbi\tvaae1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 5), OPE_XT,	"tlbi\tvale1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 7), OPE_XT,	"tlbi\tvaale1is"	},
	{ SYSREG_ENC(1, 0, 8,  7, 0), OPE_NONE,	"tlbi\tvmalle1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 1), OPE_XT,	"tlbi\tvae1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 2), OPE_XT,	"tlbi\taside1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 3), OPE_XT,	"tlbi\tvaae1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 5), OPE_XT,	"tlbi\tvale1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 7), OPE_XT,	"tlbi\tvaale1"		},
	{ SYSREG_ENC(1, 4, 8,  0, 1), OPE_XT,	"tlbi\tipas2e1is"	},
	{ SYSREG_ENC(1, 4, 8,  0, 5), OPE_XT,	"tlbi\tipas2le1is"	},
	{ SYSREG_ENC(1, 4, 8,  3, 0), OPE_NONE,	"tlbi\talle2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 1), OPE_XT,	"tlbi\tvae2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 4), OPE_NONE,	"tlbi\talle1is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 5), OPE_XT,	"tlbi\tvale2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 6), OPE_NONE,	"tlbi\tvmalls12e1is"	},
	{ SYSREG_ENC(1, 4, 8,  4, 1), OPE_XT,	"tlbi\tipas2e1"		},
	{ SYSREG_ENC(1, 4, 8,  4, 5), OPE_XT,	"tlbi\tipas2le1"	},
	{ SYSREG_ENC(1, 4, 8,  7, 0), OPE_NONE,	"tlbi\talle2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 1), OPE_XT,	"tlbi\tvae2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 4), OPE_NONE,	"tlbi\talle1"		},
	{ SYSREG_ENC(1, 4, 8,  7, 5), OPE_XT,	"tlbi\tvale2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 6), OPE_NONE,	"tlbi\tvmalls12e1"	},
	{ SYSREG_ENC(1, 6, 8,  3, 0), OPE_NONE,	"tlbi\talle3is"		},
	{ SYSREG_ENC(1, 6, 8,  3, 1), OPE_XT,	"tlbi\tvae3is"		},
	{ SYSREG_ENC(1, 6, 8,  3, 5), OPE_XT,	"tlbi\tvale3is"		},
	{ SYSREG_ENC(1, 6, 8,  7, 0), OPE_NONE,	"tlbi\talle3"		},
	{ SYSREG_ENC(1, 6, 8,  7, 1), OPE_XT,	"tlbi\tvae3"		},
	{ SYSREG_ENC(1, 6, 8,  7, 5), OPE_XT,	"tlbi\tvale3"		}
};

OP5FUNC(op_sys, op1, CRn, CRm, op2, Rt)
{
	uint32_t code;
	size_t i;

	/* ALIAS: at,dc,ic,sys,tlbi */
	code = SYSREG_ENC(1, op1, CRn, CRm, op2);
	for (i = 0; i < __arraycount(op_sys_table); i++) {
		if (op_sys_table[i].code != code)
			continue;

		if (((op_sys_table[i].flags & OPE_XT) != 0) &&
		    (Rt != 31)) {
			PRINTF("%s, %s\n",
			    op_sys_table[i].opname,
			    ZREGNAME(1, Rt));
		} else if (Rt != 31) {
#if 0
			/* Rt suppressed, but Rt field is not a xzr */
			UNDEFINED(pc, insn, "illegal Rt");
#else
			/* fallback to sys instruction */
			break;
#endif
		} else {
			PRINTF("%s\n",
			    op_sys_table[i].opname);
		}
		return;
	}

	/* default, sys instruction */
	PRINTF("sys\t#%"PRIu64", %s, %s, #%"PRIu64", %s\n",
	    op1,
	    CREGNAME(CRn),
	    CREGNAME(CRm),
	    op2,
	    ZREGNAME(1,Rt));
}

OP1FUNC(op_b, imm26)
{
	PRINTF("b\t");
	PRINTADDR(SignExtend(26, imm26, 4) + pc);
	PRINTF("\n");
}

OP2FUNC(op_b_cond, imm19, cond)
{
	PRINTF("b.%s\t", CONDNAME(cond));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP6FUNC(op_bfi, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: bfm,bfxil */
	/* it is not disassembled as bfm */
	if (imms < immr) {
		PRINTF("bfi\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else {
		PRINTF("bfxil\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms -immr + 1) & (bitwidth - 1));
	}
}

OP6FUNC(op_bic_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "bic", NULL, NULL);
}

OP6FUNC(op_bics_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "bics", NULL, NULL);
}

OP1FUNC(op_bl, imm26)
{
	PRINTF("bl\t");
	PRINTADDR(SignExtend(26, imm26, 4) + pc);
	PRINTF("\n");
}

OP1FUNC(op_blr, Rn)
{
	PRINTF("blr\t%s\n", ZREGNAME(1, Rn));
}

OP1FUNC(op_br, Rn)
{
	PRINTF("br\t%s\n", ZREGNAME(1, Rn));
}

OP1FUNC(op_brk, imm16)
{
	PRINTF("brk\t#0x%"PRIx64"\n", imm16);
}

OP3FUNC(op_cbnz, sf, imm19, Rt)
{
	PRINTF("cbnz\t%s, ", ZREGNAME(sf, Rt));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP3FUNC(op_cbz, sf, imm19, Rt)
{
	PRINTF("cbz\t%s, ", ZREGNAME(sf, Rt));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP5FUNC(op_ccmn_imm, sf, imm5, cond, Rn, nzcv)
{
	PRINTF("ccmn\t%s, #0x%"PRIx64", #0x%"PRIx64", %s\n",
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    CONDNAME(cond));
}

OP5FUNC(op_ccmn_reg, sf, Rm, cond, Rn, nzcv)
{
	PRINTF("ccmn\t%s, %s, #0x%"PRIx64", %s\n",
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    CONDNAME(cond));
}

OP5FUNC(op_ccmp_imm, sf, imm5, cond, Rn, nzcv)
{
	PRINTF("ccmp\t%s, #0x%"PRIx64", #0x%"PRIx64", %s\n",
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    CONDNAME(cond));
}

OP5FUNC(op_ccmp_reg, sf, Rm, cond, Rn, nzcv)
{
	PRINTF("ccmp\t%s, %s, #0x%"PRIx64", %s\n",
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    CONDNAME(cond));
}

OP5FUNC(op_cinc, sf, Rm, cond, Rn, Rd)
{
	/* ALIAS: cset,csinc */
	csetsel_common(di, pc, insn, sf, Rm, cond, Rn, Rd,
	    "csinc", "cset", "cinc");
}

OP5FUNC(op_csinv, sf, Rm, cond, Rn, Rd)
{
	/* ALIAS: csetm,cinv */
	csetsel_common(di, pc, insn, sf, Rm, cond, Rn, Rd,
	    "csinv", "csetm", "cinv");
}

OP1FUNC(op_clrex, CRm)
{
	if (CRm == 15) {
		PRINTF("clrex\n");
	} else {
		PRINTF("clrex\t#0x%"PRIx64"\n", CRm);
	}
}

OP3FUNC(op_cls, sf, Rn, Rd)
{
	PRINTF("cls\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

OP3FUNC(op_clz, sf, Rn, Rd)
{
	PRINTF("clz\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

OP6FUNC(op_subs_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: cmp_extreg */
	extendreg_common(di, pc, insn, sf, Rm, option, imm3, Rn, Rd,
	    "subs", "cmp");
}

OP5FUNC(op_subs_imm, sf, shift, imm12, Rn, Rd)
{
	/* ALIAS: cmp_imm */
	addsub_imm_common(di, pc, insn, sf, shift, imm12, Rn, Rd,
	    "subs", "cmp");
}

OP6FUNC(op_subs_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: negs,cmp_shiftreg */
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "subs", "negs", "cmp");
}

OP5FUNC(op_csneg, sf, Rm, cond, Rn, Rd)
{
	/* ALIAS: cneg */
	if ((Rn == Rm) && ((cond & 0xe) != 0x0e)) {
		PRINTF("cneg\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCONDNAME(cond));
	} else {
		PRINTF("csneg\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    CONDNAME(cond));
	}
}

static void
crc32_common(const disasm_interface_t *di, uint64_t pc, uint32_t insn,
    uint64_t sf, uint64_t Rm, uint64_t sz, uint64_t Rn, uint64_t Rd,
    const char *op)
{
	const char bhwx[4] = "bhwx";	/* "crc32x" + SizeChar */

	if (((sf != 0) && (sz != 3)) ||
	    ((sf == 0) && (sz == 3))) {
		UNDEFINED(pc, insn, "illegal size");
		return;
	}

	PRINTF("%s%c\t%s, %s, %s\n",
	    op, bhwx[sz & 3],
	    ZREGNAME(0, Rd),
	    ZREGNAME(0, Rn),
	    ZREGNAME(sf, Rm));
}

OP5FUNC(op_crc32, sf, Rm, sz, Rn, Rd)
{
	crc32_common(di, pc, insn, sf, Rm, sz, Rn, Rd, "crc32");
}

OP5FUNC(op_crc32c, sf, Rm, sz, Rn, Rd)
{
	crc32_common(di, pc, insn, sf, Rm, sz, Rn, Rd, "crc32c");
}

OP5FUNC(op_csel, sf, Rm, cond, Rn, Rd)
{
	PRINTF("csel\t%s, %s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    CONDNAME(cond));
}

OP2FUNC(op_dcps, imm16, ll)
{
	if (ll == 0) {
		UNDEFINED(pc, insn, "illegal level");
		return;
	}

	if (imm16 == 0)
		PRINTF("dcps%"PRIu64"\n", ll);
	else
		PRINTF("dcps%"PRIu64"\t#0x%"PRIx64"\n", ll, imm16);
}

OP0FUNC(op_drps)
{
	PRINTF("drps\n");
}

OP1FUNC(op_dmb, CRm)
{
	PRINTF("dmb\t%s\n", BARRIERNAME(CRm));
}

OP1FUNC(op_dsb, CRm)
{
	PRINTF("dsb\t%s\n", BARRIERNAME(CRm));
}

OP6FUNC(op_eon_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "eon", NULL, NULL);
}

OP6FUNC(op_eor_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("eor\t%s, %s, #0x%"PRIx64"\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, imms, immr));
}

OP6FUNC(op_eor_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "eor", NULL, NULL);
}

OP0FUNC(op_eret)
{
	PRINTF("eret\n");
}

OP6FUNC(op_ror_imm, sf, n, Rm, imms, Rn, Rd)
{
	if (((sf ^ n) != 0) || (n == 0 && imms >= 0x20)) {
		UNDEFINED(pc, insn, "illegal sf and N");
		return;
	}

	/* ALIAS: extr */
	if (Rn == Rm) {
		PRINTF("ror\t%s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    imms);
	} else {
		PRINTF("extr\t%s, %s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    imms);
	}
}

OP2FUNC(op_hint, CRm, op2)
{
	const uint64_t op = CRm << 3 | op2;

	/* ALIAS: nop,sev,sevl,wfe,wfi,yield */
	switch (op) {
	case 0:
		PRINTF("nop\n");
		break;
	case 1:
		PRINTF("yield\n");
		break;
	case 2:
		PRINTF("wfe\n");
		break;
	case 3:
		PRINTF("wfi\n");
		break;
	case 4:
		PRINTF("sev\n");
		break;
	case 5:
		PRINTF("sevl\n");
		break;
	default:
		PRINTF("hint\t#0x%"PRIx64"\n", op);
		break;
	}
}

OP1FUNC(op_hlt, imm16)
{
	PRINTF("hlt\t#0x%"PRIx64"\n", imm16);
}

OP1FUNC(op_hvc, imm16)
{
	PRINTF("hvc\t#0x%"PRIx64"\n", imm16);
}

OP1FUNC(op_isb, CRm)
{
	if (CRm == 15)
		PRINTF("isb\n");
	else
		PRINTF("isb\t#0x%"PRIx64"\n", CRm);
}

OP3FUNC(op_ldar, size, Rn, Rt)
{
	PRINTF("ldar\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldarb, Rn, Rt)
{
	PRINTF("ldarb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldarh, Rn, Rt)
{
	PRINTF("ldarh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP4FUNC(op_ldaxp, size, Rt2, Rn, Rt)
{
	PRINTF("ldaxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_ldaxr, size, Rn, Rt)
{
	PRINTF("ldaxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldaxrb, Rn, Rt)
{
	PRINTF("ldaxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldaxrh, Rn, Rt)
{
	PRINTF("ldaxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP5FUNC(op_ldnp, sf, imm7, Rt2, Rn, Rt)
{
	if (imm7 == 0) {
		PRINTF("ldnp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldnp\t%s, %s, [%s,#%"PRId64"]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

OP5FUNC(op_ldp_postidx, sf, imm7, Rt2, Rn, Rt)
{
	PRINTF("ldp\t%s, %s, [%s],#%"PRId64"\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

OP5FUNC(op_ldp_preidx, sf, imm7, Rt2, Rn, Rt)
{
	PRINTF("ldp\t%s, %s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

OP5FUNC(op_ldp_signed, sf, imm7, Rt2, Rn, Rt)
{
	if (imm7 == 0) {
		PRINTF("ldp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldp\t%s, %s, [%s,#%"PRId64"]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

OP4FUNC(op_ldpsw_postidx, imm7, Rt2, Rn, Rt)
{
	PRINTF("ldpsw\t%s, %s, [%s],#%"PRId64"\n",
	    ZREGNAME(1, Rt),
	    ZREGNAME(1, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, 4));
}

OP4FUNC(op_ldpsw_preidx, imm7, Rt2, Rn, Rt)
{
	PRINTF("ldpsw\t%s, %s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(1, Rt),
	    ZREGNAME(1, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, 4));
}

OP4FUNC(op_ldpsw_signed, imm7, Rt2, Rn, Rt)
{
	if (imm7 == 0) {
		PRINTF("ldpsw\t%s, %s, [%s]\n",
		    ZREGNAME(1, Rt),
		    ZREGNAME(1, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldpsw\t%s, %s, [%s,#%"PRId64"]\n",
		    ZREGNAME(1, Rt),
		    ZREGNAME(1, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, 4));
	}
}

OP4FUNC(op_ldr_immpostidx, size, imm9, Rn, Rt)
{
	PRINTF("ldr\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldr_immpreidx, size, imm9, Rn, Rt)
{
	PRINTF("ldr\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldr_immunsign, size, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldr\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

OP3FUNC(op_ldr_literal, size, imm19, Rt)
{
	PRINTF("ldr\t%s, ", ZREGNAME(size, Rt));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP6FUNC(op_ldr_reg, size, Rm, option, shift, Rn, Rt)
{
	regoffset_x_common(di, pc, insn, size, Rm, option, shift, Rn, Rt,
	    "ldr");
}

OP3FUNC(op_ldrb_immpostidx, imm9, Rn, Rt)
{
	PRINTF("ldrb\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrb_immpreidx, imm9, Rn, Rt)
{
	PRINTF("ldrb\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrb_immunsign, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

OP5FUNC(op_ldrb_reg, Rm, option, shift, Rn, Rt)
{
	regoffset_b_common(di, pc, insn, Rm, option, shift, Rn, Rt, "ldrb");
}

OP3FUNC(op_ldrh_immpostidx, imm9, Rn, Rt)
{
	PRINTF("ldrh\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrh_immpreidx, imm9, Rn, Rt)
{
	PRINTF("ldrh\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrh_immunsign, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

OP5FUNC(op_ldrh_reg, Rm, option, shift, Rn, Rt)
{
	regoffset_h_common(di, pc, insn, Rm, option, shift, Rn, Rt, "ldrh");
}

OP4FUNC(op_ldrsb_immpostidx, opc, imm9, Rn, Rt)
{
	PRINTF("ldrsb\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldrsb_immpreidx, opc, imm9, Rn, Rt)
{
	PRINTF("ldrsb\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldrsb_immunsign, opc, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldrsb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

OP6FUNC(op_ldrsb_reg, opc, Rm, option, shift, Rn, Rt)
{
	regoffset_b_common(di, pc, insn, Rm, option, shift, Rn, Rt, "ldrsb");
}

OP4FUNC(op_ldrsh_immpostidx, opc, imm9, Rn, Rt)
{
	PRINTF("ldrsh\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldrsh_immpreidx, opc, imm9, Rn, Rt)
{
	PRINTF("ldrsh\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_ldrsh_immunsign, opc, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldrsh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

OP6FUNC(op_ldrsh_reg, opc, Rm, option, shift, Rn, Rt)
{
	regoffset_h_common(di, pc, insn, Rm, option, shift, Rn, Rt, "ldrsh");
}

OP3FUNC(op_ldrsw_immpostidx, imm9, Rn, Rt)
{
	PRINTF("ldrsw\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(1, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrsw_immpreidx, imm9, Rn, Rt)
{
	PRINTF("ldrsw\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(1, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_ldrsw_immunsign, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("ldrsw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsw\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 4));
	}
}

OP2FUNC(op_ldrsw_literal, imm19, Rt)
{
	PRINTF("ldrsw\t%s, ", ZREGNAME(1, Rt));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP5FUNC(op_ldrsw_reg, Rm, option, shift, Rn, Rt)
{
	regoffset_w_common(di, pc, insn, Rm, option, shift, Rn, Rt, "ldrsw");
}

OP4FUNC(op_ldtr, size, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtr\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_ldtrb, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

OP3FUNC(op_ldtrh, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

OP4FUNC(op_ldtrsb, opc, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtrsb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP4FUNC(op_ldtrsh, opc, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtrsh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_ldtrsw, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldtrsw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsw\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP4FUNC(op_ldur, size, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldur\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldur\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_ldurb, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldurb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldurb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_ldurh, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldurh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldurh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP4FUNC(op_ldursb, opc, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldursb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP4FUNC(op_ldursh, opc, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldursh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_ldursw, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("ldursw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursw\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP4FUNC(op_ldxp, size, Rt2, Rn, Rt)
{
	PRINTF("ldxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_ldxr, size, Rn, Rt)
{
	PRINTF("ldxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldxrb, Rn, Rt)
{
	PRINTF("ldxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_ldxrh, Rn, Rt)
{
	PRINTF("ldxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP6FUNC(op_ubfm, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: lsr_imm,ubfiz,ubfm,ubfx,uxtb,uxth */
	if ((imms != (bitwidth - 1)) && ((imms + 1) == immr)) {
		PRINTF("lsl\t%s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    bitwidth - immr);
	} else if (imms == (bitwidth - 1)) {
		PRINTF("lsr\t%s, %s, #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr);
	} else if (imms < immr) {
		PRINTF("ubfiz\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else if (BFXPreferred(sf, 1, imms, immr)) {
		PRINTF("ubfx\t%s, %s, #%"PRIu64", #%"PRIu64"\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms - immr + 1) & (bitwidth - 1));
	} else if ((immr == 0) && (imms == 7)) {
		PRINTF("uxtb\t%s, %s\n",
		    ZREGNAME(0, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 15)) {
		PRINTF("uxth\t%s, %s\n",
		    ZREGNAME(0, Rd),
		    ZREGNAME(0, Rn));
	} else {
		UNDEFINED(pc, insn, "undefined");
	}
}

OP4FUNC(op_lsl_reg, sf, Rm, Rn, Rd)
{
	/* ALIAS: lslv */
	/* "lsl" always the preferred disassembly */
	PRINTF("lsl\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP4FUNC(op_lsr_reg, sf, Rm, Rn, Rd)
{
	/* ALIAS: lsrv */
	/* "lsr" always the preferred disassembly */
	PRINTF("lsr\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP5FUNC(op_madd, sf, Rm, Ra, Rn, Rd)
{
	/* ALIAS: mul */
	if (Ra == 31) {
		PRINTF("mul\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("madd\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    ZREGNAME(sf, Ra));
	}
}

OP5FUNC(op_msub, sf, Rm, Ra, Rn, Rd)
{
	/* ALIAS: mneg */
	if (Ra == 31) {
		PRINTF("mneg\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("msub\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    ZREGNAME(sf, Ra));
	}
}

OP6FUNC(op_orr_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	/* ALIAS: mov_bmimm */
#if 1
	/* to distinguish from mov_iwimm */
	if ((Rn == 31) && !MoveWidePreferred(sf, n, imms, immr)) {
#else
	/* "orr Rd, XZR, #imm" -> "mov Rd, #imm" */
	(void)MoveWidePreferred;
	if (Rn == 31) {
#endif
		PRINTF("mov\t%s, #0x%"PRIx64"\n",
		    SREGNAME(sf, Rd),
		    DecodeBitMasks(sf, n, imms, immr));
	} else {
		PRINTF("orr\t%s, %s, #0x%"PRIx64"\n",
		    SREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	}
}

OP4FUNC(op_movn, sf, hw, imm16, Rd)
{
	const uint64_t mask = (sf == 0) ? 0xffffffff : 0xffffffffffffffffUL;

	if ((sf == 0) && (hw >= 2)) {
		UNDEFINED(pc, insn, "illegal size");
		return;
	}

	/* ALIAS: mov_iwimm */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("mov\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    (~(ZeroExtend(16, imm16, 1) & mask)) & mask);
	} else {
		/* movn */
		const uint64_t shift = hw * 16;
		PRINTF("mov\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    ~(ZeroExtend(16, imm16, 1) << shift) & mask);
	}
}

OP6FUNC(op_orr_reg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: mov_reg */
	if ((Rn == 31) && (imm6 == 0)) {
		PRINTF("mov\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
		    "orr", NULL, NULL);
	}
}

OP4FUNC(op_movz, sf, hw, imm16, Rd)
{
	/* ALIAS: mov_wimm */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("mov\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		const int shift = hw * 16;
#if 0
		PRINTF("movz\t%s, #0x%lx, lsl #%d\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
#else
		/* same as objdump */
		PRINTF("mov\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1) << shift);
#endif
	}
}

OP4FUNC(op_movk, sf, hw, imm16, Rd)
{
	const int shift = hw * 16;

	if (hw == 0) {
		PRINTF("movk\t%s, #0x%"PRIx64"\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		PRINTF("movk\t%s, #0x%"PRIx64", lsl #%d\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
	}
}

OP6FUNC(op_mrs, op0, op1, CRn, CRm, op2, Rt)
{
	char buf[SYSREGNAMEBUFLEN];

	PRINTF("mrs\t%s, %s\n",
	    ZREGNAME(1, Rt),
	    RSYSREGNAME(buf, sizeof(buf), op0, op1, CRn, CRm, op2));
}

OP6FUNC(op_msr, op0, op1, CRn, CRm, op2, Rt)
{
	char buf[SYSREGNAMEBUFLEN];

	PRINTF("msr\t%s, %s\n",
	    WSYSREGNAME(buf, sizeof(buf), op0, op1, CRn, CRm, op2),
	    ZREGNAME(1, Rt));
}

OP3FUNC(op_msr_imm, op1, CRm, op2)
{
	const char *pstatefield;

#define MSRIMM_OP(op1, op2)	(((op1) << 3) | (op2))

	switch (MSRIMM_OP(op1, op2)) {
	case MSRIMM_OP(0, 5):
		pstatefield = "spsel";
		break;
	case MSRIMM_OP(3, 6):
		pstatefield = "daifset";
		break;
	case MSRIMM_OP(3, 7):
		pstatefield = "daifclr";
		break;
	default:
		UNDEFINED(pc, insn, "illegal op1/op2");
		return;
	}

	PRINTF("msr\t%s, #0x%"PRIx64"\n",
	    pstatefield, CRm);
}

OP6FUNC(op_orn, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: mvn */
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "orn", "mvn", NULL);
}

OP6FUNC(op_sub_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: neg */
	shiftreg_common(di, pc, insn, sf, shift, Rm, imm6, Rn, Rd,
	    "sub", "neg", NULL);
}

OP4FUNC(op_sbc, sf, Rm, Rn, Rd)
{
	/* ALIAS: ngc */
	if (Rn == 31) {
		PRINTF("ngc\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("sbc\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
}

OP4FUNC(op_sbcs, sf, Rm, Rn, Rd)
{
	/* ALIAS: ngcs */
	if (Rn == 31) {
		PRINTF("ngcs\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("sbcs\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
}

OP3FUNC(op_prfm_imm, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("prfm\t%s, [%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("prfm\t%s, [%s,#%"PRId64"]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm12, 8));
	}
}

OP2FUNC(op_prfm_literal, imm19, Rt)
{
	PRINTF("prfm\t%s, ", PREFETCHNAME(Rt));
	PRINTADDR(SignExtend(19, imm19, 4) + pc);
	PRINTF("\n");
}

OP5FUNC(op_prfm_reg, Rm, option, shift, Rn, Rt)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("prfm\t%s, [%s,%s%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		PRINTF("prfm\t%s, [%s,%s,%s #%d]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    3);
	}
}

OP3FUNC(op_prfum, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("prfum\t%s, [%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("prfum\t%s, [%s,#%"PRId64"]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP1FUNC(op_ret, Rn)
{
	if (Rn == 30)
		PRINTF("ret\n");
	else
		PRINTF("ret\t%s\n", ZREGNAME(1, Rn));
}

OP4FUNC(op_rev, sf, opc, Rn, Rd)
{
	/*
	 * sf opc insn
	 * -- --- -------------
	 * 0  00  rbit    Wd,Wn
	 * 0  01  rev16   Wd,Wn
	 * 0  10  rev     Wd,Wn
	 * 0  11  undefined
	 * 1  00  rbit    Xd,Xn
	 * 1  01  rev16   Xd,Xn
	 * 1  10  rev32   Xd,Xn
	 * 1  11  rev     Xd,Xn
	 */
	const char *const opcode[2][4] = {
		{ "rbit", "rev16", "rev",   NULL  },
		{ "rbit", "rev16", "rev32", "rev" }
	};
	const char *const op = opcode[sf][opc];

	if (op == NULL) {
		UNDEFINED(pc, insn, "undefined");
		return;
	}

	PRINTF("%s\t%s, %s\n",
	    op,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

OP4FUNC(op_ror_reg, sf, Rm, Rn, Rd)
{
	/* ALIAS: rorv */
	/* "ror" always the preferred disassembly */
	PRINTF("ror\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP4FUNC(op_sdiv, sf, Rm, Rn, Rd)
{
	PRINTF("sdiv\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP4FUNC(op_smaddl, Rm, Ra, Rn, Rd)
{
	/* ALIAS: smull */
	if (Ra == 31) {
		PRINTF("smull\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm));
	} else {
		PRINTF("smaddl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm),
		    ZREGNAME(1, Ra));
	}
}

OP1FUNC(op_smc, imm16)
{
	PRINTF("smc\t#0x%"PRIx64"\n", imm16);
}

OP4FUNC(op_smsubl, Rm, Ra, Rn, Rd)
{
	/* ALIAS: smnegl */
	if (Ra == 31) {
		PRINTF("smnegl\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("smsubl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

OP3FUNC(op_smulh, Rm, Rn, Rd)
{
	PRINTF("smulh\t%s, %s, %s\n",
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

OP3FUNC(op_stlr, size, Rn, Rt)
{
	PRINTF("stlr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_stlrb, Rn, Rt)
{
	PRINTF("stlrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP2FUNC(op_stlrh, Rn, Rt)
{
	PRINTF("stlrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP5FUNC(op_stlxp, size, Rs, Rt2, Rn, Rt)
{
	PRINTF("stlxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

OP4FUNC(op_stlxr, size, Rs, Rn, Rt)
{
	PRINTF("stlxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_stlxrb, Rs, Rn, Rt)
{
	PRINTF("stlxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_stlxrh, Rs, Rn, Rt)
{
	PRINTF("stlxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP5FUNC(op_stnp, sf, imm7, Rt2, Rn, Rt)
{
	if (imm7 == 0) {
		PRINTF("stnp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stnp\t%s, %s, [%s,#%"PRId64"]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

OP5FUNC(op_stp_postidx, sf, imm7, Rt2, Rn, Rt)
{
	PRINTF("stp\t%s, %s, [%s],#%"PRId64"\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

OP5FUNC(op_stp_preidx, sf, imm7, Rt2, Rn, Rt)
{
	PRINTF("stp\t%s, %s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

OP5FUNC(op_stp_signed, sf, imm7, Rt2, Rn, Rt)
{
	if (imm7 == 0) {
		PRINTF("stp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stp\t%s, %s, [%s,#%"PRId64"]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

OP4FUNC(op_str_immpostidx, size, imm9, Rn, Rt)
{
	PRINTF("str\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_str_immpreidx, size, imm9, Rn, Rt)
{
	PRINTF("str\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP4FUNC(op_str_immunsign, size, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("str\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("str\t%s, [%s,#%"PRIu64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

OP6FUNC(op_str_reg, size, Rm, option, shift, Rn, Rt)
{
	regoffset_x_common(di, pc, insn, size, Rm, option, shift, Rn, Rt,
	    "str");
}

OP3FUNC(op_strb_immpostidx, imm9, Rn, Rt)
{
	PRINTF("strb\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_strb_immpreidx, imm9, Rn, Rt)
{
	PRINTF("strb\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_strb_immunsign, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("strb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("strb\t%s, [%s,#%"PRIu64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

OP5FUNC(op_strb_reg, Rm, option, shift, Rn, Rt)
{
	regoffset_b_common(di, pc, insn, Rm, option, shift, Rn, Rt, "strb");
}

OP3FUNC(op_strh_immpostidx, imm9, Rn, Rt)
{
	PRINTF("strh\t%s, [%s],#%"PRId64"\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_strh_immpreidx, imm9, Rn, Rt)
{
	PRINTF("strh\t%s, [%s,#%"PRId64"]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP3FUNC(op_strh_immunsign, imm12, Rn, Rt)
{
	if (imm12 == 0) {
		PRINTF("strh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("strh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

OP5FUNC(op_strh_reg, Rm, option, shift, Rn, Rt)
{
	regoffset_h_common(di, pc, insn, Rm, option, shift, Rn, Rt, "strh");
}

OP4FUNC(op_sttr, size, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("sttr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttr\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_sttrb, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("sttrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttrb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

OP3FUNC(op_sttrh, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("sttrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttrh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

OP4FUNC(op_stur, size, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("stur\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stur\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_sturb, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("sturb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sturb\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP3FUNC(op_sturh, imm9, Rn, Rt)
{
	if (imm9 == 0) {
		PRINTF("sturh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sturh\t%s, [%s,#%"PRId64"]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

OP5FUNC(op_stxp, size, Rs, Rt2, Rn, Rt)
{
	PRINTF("stxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

OP4FUNC(op_stxr, size, Rs, Rn, Rt)
{
	PRINTF("stxr\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_stxrb, Rs, Rn, Rt)
{
	PRINTF("stxrb\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP3FUNC(op_stxrh, Rs, Rn, Rt)
{
	PRINTF("stxrh\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

OP6FUNC(op_sub_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	extendreg_common(di, pc, insn, sf, Rm, option, imm3, Rn, Rd,
	    "sub", NULL);
}

OP5FUNC(op_sub_imm, sf, shift, imm12, Rn, Rd)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	PRINTF("sub\t%s, %s, #0x%"PRIx64"%s\n",
	    SREGNAME(sf, Rd),
	    SREGNAME(sf, Rn),
	    ZeroExtend(12, imm12, 1),
	    SHIFTOP2(shift, "", ", lsl #12"));
}

OP1FUNC(op_svc, imm16)
{
	PRINTF("svc\t#0x%"PRIx64"\n",
	    imm16);
}

OP5FUNC(op_sysl, op1, CRn, CRm, op2, Rt)
{
	PRINTF("sysl\t%s, #%"PRIu64", %s, %s, #%"PRIu64"\n",
	    ZREGNAME(1, Rt),
	    op1,
	    CREGNAME(CRn),
	    CREGNAME(CRm),
	    op2);
}

OP4FUNC(op_tbnz, b5, b40, imm14, Rt)
{
	uint64_t bit = (b5 << 5) + b40;

	PRINTF("tbnz\t%s, #%"PRIu64", ",
	    ZREGNAME(b5, Rt),
	    bit);
	PRINTADDR(SignExtend(14, imm14, 4) + pc);
	PRINTF("\n");
}

OP4FUNC(op_tbz, b5, b40, imm14, Rt)
{
	uint64_t bit = (b5 << 5) + b40;

	PRINTF("tbz\t%s, #%"PRIu64", ",
	    ZREGNAME(b5, Rt),
	    bit);
	PRINTADDR(SignExtend(14, imm14, 4) + pc);
	PRINTF("\n");
}

OP4FUNC(op_udiv, sf, Rm, Rn, Rd)
{
	PRINTF("udiv\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

OP4FUNC(op_umaddl, Rm, Ra, Rn, Rd)
{
	/* ALIAS: umull */
	if (Ra == 31) {
		PRINTF("umull\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm));
	} else {
		PRINTF("umaddl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm),
		    ZREGNAME(1, Ra));
	}
}

OP4FUNC(op_umsubl, Rm, Ra, Rn, Rd)
{
	/* ALIAS: umnegl */
	if (Ra == 31) {
		PRINTF("umnegl\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("umsubl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

OP3FUNC(op_umulh, Rm, Rn, Rd)
{
	PRINTF("umulh\t%s, %s, %s\n",
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

/*
 * load/store SIMD instructions
 */
OP6FUNC(op_simd_ldstnp, opc, l, imm7, Rt2, Rn, Rt)
{
	const char *op = (l == 0) ? "stnp" : "ldnp";
	const int regsz = (opc & 3) + 2;

	if (opc == 3) {
		UNDEFINED(pc, insn, "illegal opc");
		return;
	}

	if (imm7 == 0) {
		PRINTF("%s\t%s, %s, [%s]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    FREGNAME(regsz, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%s\t%s, %s, [%s,#%"PRId64"]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    FREGNAME(regsz, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (4 << opc)));
	}
}

OP6FUNC(op_simd_ldstp_postidx, opc, l, imm7, Rt2, Rn, Rt)
{
	const char *op = (l == 0) ? "stp" : "ldp";
	const int regsz = (opc & 3) + 2;

	PRINTF("%s\t%s, %s, [%s],#%"PRId64"\n",
	    op,
	    FREGNAME(regsz, Rt),
	    FREGNAME(regsz, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (4 << opc)));
}

OP6FUNC(op_simd_ldstp_preidx, opc, l, imm7, Rt2, Rn, Rt)
{
	const char *op = (l == 0) ? "stp" : "ldp";
	const int regsz = (opc & 3) + 2;

	PRINTF("%s\t%s, %s, [%s,#%"PRId64"]!\n",
	    op,
	    FREGNAME(regsz, Rt),
	    FREGNAME(regsz, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (4 << opc)));
}

OP6FUNC(op_simd_ldstp_signed, opc, l, imm7, Rt2, Rn, Rt)
{
	const char *op = (l == 0) ? "stp" : "ldp";
	const int regsz = (opc & 3) + 2;

	if (opc == 3) {
		UNDEFINED(pc, insn, "illegal opc");
		return;
	}

	if (imm7 == 0) {
		PRINTF("%s\t%s, %s, [%s]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    FREGNAME(regsz, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%s\t%s, %s, [%s,#%"PRId64"]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    FREGNAME(regsz, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (4 << opc)));
	}
}

static inline int
simd_ldstr_regsz(uint64_t size, uint64_t opc)
{
	if ((opc & 2) == 0)
		return size;
	if (size == 0)
		return 4;
	return -1;
}

OP5FUNC(op_simd_ldstr_immpostidx, size, opc, imm9, Rn, Rt)
{
	const char *op = ((opc & 1) == 0) ? "str" : "ldr";
	int regsz;

	if ((regsz = simd_ldstr_regsz(size, opc)) < 0) {
		UNDEFINED(pc, insn, "illegal size/opc");
		return;
	}

	PRINTF("%s\t%s, [%s],#%"PRId64"\n",
	    op,
	    FREGNAME(regsz, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP5FUNC(op_simd_ldstr_immpreidx, size, opc, imm9, Rn, Rt)
{
	const char *op = ((opc & 1) == 0) ? "str" : "ldr";
	int regsz;

	if ((regsz = simd_ldstr_regsz(size, opc)) < 0) {
		UNDEFINED(pc, insn, "illegal size/opc");
		return;
	}

	PRINTF("%s\t%s, [%s,#%"PRId64"]!\n",
	    op,
	    FREGNAME(regsz, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

OP5FUNC(op_simd_ldstr_immunsign, size, opc, imm12, Rn, Rt)
{
	const char *op = ((opc & 1) == 0) ? "str" : "ldr";
	int regsz;

	if ((regsz = simd_ldstr_regsz(size, opc)) < 0) {
		UNDEFINED(pc, insn, "illegal size/opc");
		return;
	}

	if (imm12 == 0) {
		PRINTF("%s\t%s, [%s]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%s\t%s, [%s,#%"PRIu64"]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1 << regsz));
	}
}

OP7FUNC(op_simd_ldstr_reg, size, opc, Rm, option, S, Rn, Rt)
{
	const char *op = ((opc & 1) == 0) ? "str" : "ldr";
	int regsz, r;

	if ((regsz = simd_ldstr_regsz(size, opc)) < 0) {
		UNDEFINED(pc, insn, "illegal size/opc");
		return;
	}

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (S == 0) {
		PRINTF("%s\t%s, [%s,%s%s]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		u_int amount = regsz;
		PRINTF("%s\t%s, [%s,%s,%s #%u]\n",
		    op,
		    FREGNAME(regsz, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    amount);
	}
}


/*
 * SIMD instructions except load/store insns are not supported (yet?),
 * and disassembled as 'undefined'.
 */
struct bitpos {
	uint8_t pos;
	uint8_t width;
};

struct insn_info {
	uint32_t mask;
	uint32_t pattern;
#define INSN_MAXARG	8
	struct bitpos bitinfo[INSN_MAXARG];
	OPFUNC_DECL(void (*opfunc),,,,,,,,);
};

#include "table.h"

#define WIDTHMASK(w)	(0xffffffff >> (32 - (w)))

void
disasm_insn(const disasm_interface_t *di, uintptr_t loc, uint32_t insn)
{
	uint64_t args[INSN_MAXARG];
	unsigned int i, j;

	for (i = 0; i < __arraycount(insn_tables); i++) {
		if ((insn & insn_tables[i].mask) != insn_tables[i].pattern)
			continue;

		/* extract operands */
		for (j = 0; j < INSN_MAXARG; j++) {
			if (insn_tables[i].bitinfo[j].width == 0)
				break;
			args[j] = (insn >> insn_tables[i].bitinfo[j].pos) &
			    WIDTHMASK(insn_tables[i].bitinfo[j].width);
		}
		insn_tables[i].opfunc(di, loc, insn,
		    args[0], args[1], args[2], args[3],
		    args[4], args[5], args[6], args[7]);
		break;
	}
}

uintptr_t
disasm(const disasm_interface_t *di, uintptr_t loc)
{
	uint32_t insn;

	insn = di->di_readword(loc);
	disasm_insn(di, loc, insn);

	/* return next address */
	return loc + sizeof(insn);
}
