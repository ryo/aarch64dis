
CC	?= cc
CXX	?= g++
DBG	= -O3
#DBG	+= -g
CFLAGS	= ${DBG} -pipe -I/usr/local/include
CFLAGS +=-Wall \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wpointer-arith \
	-Wno-sign-compare \
	-Wa,--fatal-warnings \
	-Wreturn-type \
	-Wswitch \
	-Wshadow \
	-Wcast-qual \
	-Wwrite-strings \
	-Wextra \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-Wold-style-definition \
	-Wsign-compare \
	-Wformat=2 \
	-Wno-format-zero-length \
	-Werror
CXXAGS	= ${CFLAGS:S/-Wno-traditional//}
LD	= ${CC}
MKDEP	= mkdep
LIBS	= -L/usr/local/lib

PROGRAM	= disasm_test
SRCS	= test.c disasm.c
OBJS	= $(SRCS)
OBJS	:= $(OBJS:.c=.o)
OBJS	:= $(OBJS:.cc=.o)
OBJS	:= $(OBJS:.cpp=.o)
OBJS	:= $(OBJS:.cxx=.o)

.c.o:
	$(CC) -c $(CFLAGS) $<

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $<


$(PROGRAM): $(OBJS)
	$(LD) $(OBJS) -o $(PROGRAM) $(LIBS)

depend:
	$(MKDEP) $(SRCS)

clean:
	-rm -f *.o $(PROGRAM)

cleandir: clean
	-rm -f .depend

test:
	aarch64--netbsd-objdump -Dr ~/tmp/netbsd/work.evbarm64-el/tree/sbin/init | ./disasm_test | less -r

testn:
	aarch64--netbsd-objdump -Dr ~/tmp/netbsd/sys/arch/evbarm//compile/RPI64/netbsd | ./disasm_test | less -r

testnn:
	aarch64--netbsd-objdump -Dr ~/tmp/netbsd/sys/arch/evbarm//compile/RPI64/netbsd | ./disasm_test | egrep '^(ORIG|ERR)' > r
	grep -v 'ORIG.*\.word' r | less -r -p 'ORIG............................'

testb:
	aarch64--netbsd-clang -mcrc -c bin.S
	aarch64--netbsd-objdump -Dr bin.o | ./disasm_test | less -r

testc:
	aarch64--netbsd-objdump -Dr ~/tmp/netbsd/work.evbarm64-el/tree/lib/libc.so | ./disasm_test | less -r

