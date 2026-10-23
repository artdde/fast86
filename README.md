# fast86

Same-ISA x86_64 copy-and-patch translator. Guest and host are both
x86_64, so ALU ops are copied through instead of being lowered through
TCG IR.

This is a userspace Linux ELF runner (static binaries), not a macOS
system emulator. It exists to measure how much QEMU TCG leaves on the
table when the ISAs already match — and to get a libc-capable runner
without paying the TCG tax.

```
make
make test
./compare.sh
./fast86 benches/int
./fast86 --direct /path/to/static-hello
```

`--direct` identity-maps the binary, patches `syscall` to `int3`, and
runs the guest bytes on the real CPU. Host/guest FS bases are switched
around the trap so glibc TLS/malloc work.

Measured on this host (no KVM; `/dev/kvm` restricted). Same freestanding
x86_64 binaries unless noted.

| bench | native | fast86 | `--direct` | vs native |
|-------|--------|--------|------------|-----------|
| int   | 0.53s  | 0.63s  | 0.58s      | 1.2×      |
| mem   | 0.17s  | 0.19s  | 0.16s      | ~1×       |
| fib O0 (38) | 0.39s | 0.81s | 0.36s | 2.1× (63M CALL/RET) |
| fib O2 (38) | 0.08s | 0.12s | 0.09s | 1.5×, 14 exits |
| static libc hello | instant | **works** (16 syscalls) | **works** | — |

Integer loops are the honest TCG comparison: TCG pays the IR tax on
every add/xor. fast86 copies those insns and backpatches the backward
`jne` to a native jump, so the hot loop runs on the real CPU.

Recursive `fib` used to take a C helper on every call/ret. Direct
calls are `push`+shadow+`jmp` into the code cache; returns pop the
shadow and jump. Mid-block JCCs are mapped per-instruction, so the O2
unrolled loop stays native (14 exits instead of 6.6 million).

Translator-mode static glibc hello now runs to completion (was
escaping into raw guest `syscall` after a bad RIP-relative CMOV
rewrite and a VEX length miss on `vzeroupper`).

## Still open

- O0 fib is still ~2× native: each CALL/RET pays a shadow-stack
  sequence instead of a one-byte `call`/`ret`.
- Indirect CALL/JMP still go through a C helper.

## System mode (this is the product, not QEMU)

`fast86 --system` is a same-ISA system emulator: guest RAM is identity-mapped
where the host allows, privileged ops trap into C, everything else is
copy-and-patch. QEMU TCG is the thing we time against, not the CPU.

```
./fast86 --system benches/syshello.bin     # COM1 print + HLT
./fast86 --system benches/sysloop.bin      # 80M ALU loop (0.06s here)
./fast86 --system --mem 4096 --root DIR foo.efi
```

sysloop (80M add/xor/dec) is **0.06s** on the translator. That is the
class of work TCG pays IR tax on; this path does not.

`--system` already loads and runs 64-bit PE32+ EFI images. The boot
chain now reaches OpenCore's GUI picker on this box: BOOTx64 shim →
OpenCore.efi → config.plist → OpenCanopy driver → 1024×768 GOP, with
OpenCanopy rendering frames (icons/fonts loaded through the SimpleFS
backend).

```
# stage the OpenCore ESP from /opt/macos-vm (config.plist lives at the
# OpenCore repo root, not in EFI/OC/):
F86_UEFI=1 ./fast86 --system --mem 3072 --root /path/to/esp \
    /path/to/esp/EFI/BOOT/BOOTx64.efi
# framebuffer dumps land in /tmp/f86-gop.ppm (GOP 1024x768)
```

Getting there fixed three firmware bugs: the EFI loaded-image
device-path GUID had been set to OpenCore's `mOcLoadedImageProtocolGuid`
(so OpenCore called the device-path bytes as an entry point), `CreateEvent`
wrote its dummy handle into the wrong argument slot (leaving the picker's
timer event NULL and its loop spinning), and per-image FilePath device
paths now come from the `LoadImage` DevicePath arg instead of the shim's.

## macOS recovery volume (second SimpleFS)

`--mac-root DIR` exposes a second SimpleFS volume. Point it at the files
extracted from `BaseSystem.img`'s HFS+ partition (`tools/hfsplus_extract.py`
walks the catalog; pull `System/Library/CoreServices/boot.efi` +
`SystemVersion.plist` + `PlatformSupport.plist`), and OpenCore's bless scan
finds the `macOS Base System` entry and starts `boot.efi`:

```
./fast86 --system --mem 3072 --root /tmp/esp --mac-root /tmp/mac-root \
    /tmp/esp/EFI/BOOT/BOOTx64.efi
```

Multi-volume support needed three fixes on top of the picker: `OpenVolume`
had been hardwired to the ESP handle, `FileClose` freed the second volume's
handle, and `GetInfo` returned `EFI_SUCCESS` for the Apple APFS/bless GUIDs
so OpenCore misread generic file info as APFS metadata and skipped the
predefined-path scan. `LocateDevicePath` now maps the leading volume node to
the right handle instead of always returning the ESP.

`boot.efi` currently starts, reads its NVRAM booter config and the
SMBIOS-style identifiers (`HW_BID`, `MLB`, `ROM`), then exits with
`EFI_ACCESS_DENIED` — it is missing the board identity / Apple protocols it
needs before it will load the kernel. That (plus the prelinkedkernel + SMC/
ACPI surface) is the remaining gap to the Apple logo — still on this CPU,
still not QEMU.

QEMU TCG Sequoia under `/opt/macos-vm/start.sh` is only a **baseline**
(what TCG does with the same recovery image).
