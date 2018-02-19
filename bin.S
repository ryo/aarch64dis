#
# test file
#
.text


knownbugs:
	nop



testpattern:
	ubfx	x0, x1, #0, #1
	ubfx	x0, x1, #0, #2
	ubfx	x0, x1, #0, #3
	ubfx	x0, x1, #0, #4
	ubfx	x0, x1, #0, #5
	ubfx	x0, x1, #0, #6
	ubfx	x0, x1, #0, #7
	nop
	ubfx	x0, x1, #1, #5
	ubfx	x0, x1, #2, #5
	ubfx	x0, x1, #3, #5
	ubfx	x0, x1, #4, #5
	ubfx	x0, x1, #5, #5
	ubfx	x0, x1, #6, #5
	ubfx	x0, x1, #7, #5
	nop
	nop
	nop
	uxtb	w0, w1
	uxth	w2, w3




memo:
	mov	x9, #0x4000400040004
	mov	x9, #0x1000000010
	mov	w1, #0x20002
	nop
	nop
	nop
	nop
