# Build:  make                       (uses headers of the RUNNING kernel)
#         make KDIR=/lib/modules/<version>/build
# Load:   sudo insmod securemon.ko   Unload: sudo rmmod securemon
obj-m += securemon.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
