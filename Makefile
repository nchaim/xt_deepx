MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

obj-m += xt_deepx.o

all: modules modules_install lib lib_install
clean: lib_clean modules_clean

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_clean:
	make -C ${KERNEL_DIR} M=$$PWD clean;


libxt_CFLAGS = -O3 -Wall -Wformat -g
xtlibdir = /lib/xtables
LIB_TARGET = libxt_deepx.so

lib: $(LIB_TARGET)

libxt_deepx.so: libxt_deepx.o
	gcc -shared -fPIC -o $@ $^;
libxt_deepx.o: libxt_deepx.c
	gcc ${libxt_CFLAGS} -fPIC -c -o $@ $<

lib_install:
	cp $(LIB_TARGET) $(xtlibdir)/$(LIB_TARGET)

lib_clean:
	rm -f *.o $(LIB_TARGET)

