# Build fpcap.efi with gnu-efi (Debian/Ubuntu: apt install gnu-efi).
ARCH      := x86_64
EFIINC    := /usr/include/efi
EFILIB    := /usr/lib
GNUEFILIB := /usr/lib
CRT0      := $(GNUEFILIB)/crt0-efi-$(ARCH).o
LDS       := $(GNUEFILIB)/elf_$(ARCH)_efi.lds

CFLAGS  := -I$(EFIINC) -I$(EFIINC)/$(ARCH) -I$(EFIINC)/protocol \
           -fno-stack-protector -fpic -fshort-wchar -mno-red-zone -Wall -O2 \
           -DEFI_FUNCTION_WRAPPER
LDFLAGS := -nostdlib -znocombreloc -T $(LDS) -shared -Bsymbolic \
           -L$(EFILIB) -L$(GNUEFILIB) $(CRT0)

all: fpcap.efi

fpcap.o: fpcap.c
	gcc $(CFLAGS) -c $< -o $@

fpcap.so: fpcap.o
	ld $(LDFLAGS) $< -o $@ -lefi -lgnuefi

fpcap.efi: fpcap.so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
	        -j .rela -j .rel.* -j .rela.* -j .reloc \
	        --target efi-app-$(ARCH) --subsystem=10 $< $@
	@echo "built $@"

clean:
	rm -f fpcap.o fpcap.so fpcap.efi

.PHONY: all clean
