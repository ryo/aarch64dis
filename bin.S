#
# test file
#
.text


knownbugs:
	nop



testpattern:
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
