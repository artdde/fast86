# macOS Sequoia recovery, TCG only

This is the no-KVM path. QEMU emulates the CPU in software (`-accel tcg`).
`/dev/kvm` is never opened.

Assets live in `/opt/macos-vm` (recovery image is ~3 GiB uncompressed).

```
chmod 000 /dev/kvm          # optional, not required — start.sh never enables KVM
/opt/macos-vm/start.sh      # VNC 127.0.0.1:5902
/opt/macos-vm/screendump.sh # PPM via QEMU monitor
```

Boot sequence observed on this host:

1. OVMF → OpenCore picker (`EFI` / `macOS Base System`)
2. Select **macOS Base System**
3. Apple logo (XNU starting)

First-time fetch (Apple recovery, Sequoia):

```
cd /opt/macos-vm/OSX-KVM
python3 ./fetch-macOS-v2.py --shortname sequoia
dmg2img -i BaseSystem.dmg -o BaseSystem.img
```
