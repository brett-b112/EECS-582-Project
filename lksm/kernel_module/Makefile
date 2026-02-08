obj-m += lksm.o
lksm-objs := lksm_main.o lksm_hooks.o lksm_buffer.o lksm_comm.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod lksm.ko

unload:
	sudo rmmod lksm

reload: unload all load

.PHONY: all clean load unload reload
