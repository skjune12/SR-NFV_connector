ifneq ($(KERNELRELEASE),)

obj-m:= hook.o

else

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD:= $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

.PHONY: clean

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c Module.* modules.*
