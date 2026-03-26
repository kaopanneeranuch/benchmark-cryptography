HEADER=$(wildcard *.h)
OBJS=internal-forkskinny.o skinny.o

lib: ${OBJS}
	$(AR) -rcs libforkskinnyopt32.a ${OBJS}
	rm -f *.d

%.o: %.c ${HEADER}
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -f *.o *.a *.d
