#
# test file
#
.text


knownbugs:
	nop



testpattern:
	mov	x9, #0x4000400040004
	mov	x9, #0x1000000010
	mov	w1, #0x20002
	nop
	nop
	nop
	nop
