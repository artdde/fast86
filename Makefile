CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -Wno-unused-function -fno-strict-aliasing -fno-stack-protector -fcf-protection=none -std=gnu11
LDFLAGS :=

SRC := src/decode.c src/engine.c src/sys.c src/uefi.c src/main.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean benches test

all: fast86 benches

fast86: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

src/%.o: src/%.c src/f86.h
	$(CC) $(CFLAGS) -c -o $@ $<

BFLAGS := -O2 -static -fno-pie -no-pie -nostdlib -mno-avx -mno-avx2 -fno-builtin -fno-plt

benches: benches/int benches/mem benches/fib benches/rec benches/fib0 benches/regs benches/tiny benches/correct benches/vex benches/syshello.bin benches/sysloop.bin benches/syspop.bin

benches/int: benches/int.c
	$(CC) $(BFLAGS) -o $@ $<

benches/mem: benches/mem.c
	$(CC) $(BFLAGS) -o $@ $<

benches/fib: benches/fib.c
	$(CC) $(BFLAGS) -o $@ $<

benches/rec: benches/rec.c
	$(CC) $(BFLAGS) -O0 -o $@ $<

benches/fib0: benches/fib.c
	$(CC) $(BFLAGS) -O0 -o $@ $<

benches/regs: benches/regs.c
	$(CC) $(BFLAGS) -o $@ $<

benches/tiny: benches/tiny.S
	$(CC) -nostdlib -static -fno-pie -no-pie -o $@ $<

benches/correct: benches/correct.c
	$(CC) $(BFLAGS) -o $@ $<

benches/vex: benches/vex.c
	$(CC) $(BFLAGS) -mavx2 -mbmi2 -o $@ $<

benches/syshello.elf: benches/syshello.S
	$(CC) -nostdlib -static -fno-pie -no-pie -Wl,-Ttext=0x200000 -Wl,--build-id=none -o $@ $<

benches/syshello.bin: benches/syshello.elf
	objcopy -O binary $< $@

benches/sysloop.elf: benches/sysloop.S
	$(CC) -nostdlib -static -fno-pie -no-pie -Wl,-Ttext=0x200000 -Wl,--build-id=none -o $@ $<

benches/sysloop.bin: benches/sysloop.elf
	objcopy -O binary $< $@

benches/syspop.elf: benches/syspop.S
	$(CC) -nostdlib -static -fno-pie -no-pie -Wl,-Ttext=0x200000 -Wl,--build-id=none -o $@ $<

benches/syspop.bin: benches/syspop.elf
	objcopy -O binary $< $@

lenchk: src/lenchk.c src/decode.c src/f86.h
	$(CC) $(CFLAGS) -o $@ src/lenchk.c src/decode.c

test: all lenchk
	./test.sh

clean:
	rm -f fast86 lenchk $(OBJ) benches/int benches/mem benches/fib benches/rec benches/fib0 benches/regs benches/tiny benches/correct benches/vex benches/syshello.bin benches/syshello.elf benches/sysloop.bin benches/sysloop.elf benches/syspop.bin benches/syspop.elf
