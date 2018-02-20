#
# test file
#
.text


knownbugs:
	nop



testpattern:
	adds	x0, sp, w0, uxtw
	cmn	x0, w0, uxtw

	add	sp, sp, w0, uxtw
	add	x9, sp, w0, lsl #0

	nop

	add	sp, sp, w0, uxtw
	add	sp, sp, w0, uxtw

	add	x0, x1, w0, lsl #4

	nop
	add	x9, sp, w0, lsl #0
	add	x9, x9, w0, lsl #0
	add	x9, sp, w0, sxtb #0
	add	x9, x9, w0, sxtb #0
	nop

	add	x0, x1, w0, lsl #4
	add	w0, w1, w2, lsl #4

	add	sp, sp, w0, sxtb #0
	add	sp, sp, w0, sxtb #1
	add	sp, sp, w0, sxtb #4
	add	sp, sp, x0, sxtx #0
	add	sp, sp, x0, sxtx #1
	add	sp, sp, x0, sxtx #4


	nop

	bfm	w2, w3, #10, #12
	bfm	x0, x1, #3, #4
	bfi	x1, x2, #3, #4
	bfxil	x1, x2, #3, #4



memo:
	mov	x9, #0x4000400040004
	mov	x9, #0x1000000010
	mov	w1, #0x20002
	nop
	nop
	nop
	nop
