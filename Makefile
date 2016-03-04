KDIR		:= /lib/modules/$(shell uname -r)/build/
PWD		:= $(shell pwd)
VERBOSE = 0

obj-m := pktdev.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) V=$(VERBOSE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

