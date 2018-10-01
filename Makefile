PIN_VERSION ?= pin-3.6-97554-g31f0a167d-gcc-linux
PIN_ARCHIVE = $(PIN_VERSION).tar.gz
PIN_ROOT ?= $(PWD)/$(PIN_VERSION)
RM = rm -Rf

default: all

all: ia32 intel64

.PHONY: ia32 intel64 pin

$(PIN_VERSION): 
	curl -o $(PIN_ARCHIVE) -L https://software.intel.com/sites/landingpage/pintool/downloads/$(PIN_ARCHIVE)
	tar xvzf $(PIN_ARCHIVE)
	$(RM) $(PIN_ARCHIVE)

pin: $(PIN_VERSION)

ia32: pin
	PIN_ROOT=$(PIN_ROOT) TARGET=ia32 make -C src 

intel64: pin
	PIN_ROOT=$(PIN_ROOT) TARGET=intel64 make -C src

clean:
	PIN_ROOT=$(PIN_ROOT) TARGET=intel64 make -C src clean
	PIN_ROOT=$(PIN_ROOT) TARGET=ia32 make -C src clean
	rm -f *.log out.file

.phony: test
test: ia32
	$(PIN_ROOT)/pin -t src/obj-ia32/Tracer.so -o out.file -- tests/busybox-static_1.22.0-19+b3_i386/bin/busybox echo 'toto'

.phony: pin-clean

pin-clean:
	$(RM) $(PIN_ROOT)

veryclean: clean pin-clean

