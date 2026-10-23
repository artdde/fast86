#!/usr/bin/env python3
import subprocess, time, os
os.chdir(os.path.dirname(os.path.abspath(__file__)) or ".")

def run(cmd):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dt = time.perf_counter() - t0
    return dt, p.stdout, p.returncode

have_qemu = os.path.exists("/usr/bin/qemu-x86_64")
print(f"{'bench':<10} {'native':>8} {'qemu-tcg':>8} {'fast86':>8} {'direct':>8} {'tcg/nat':>8} {'tcg/f86':>8} {'match'}")
for b in ("int", "mem", "fib", "rec", "regs", "correct"):
    path = f"./benches/{b}"
    if not os.path.exists(path):
        print(b, "missing")
        continue
    nt, no, _ = run([path])
    if have_qemu:
        qt, qo, _ = run(["qemu-x86_64", path])
    else:
        qt, qo = float("nan"), no
    ft, fo, _ = run(["./fast86", path])
    dt, do, _ = run(["./fast86", "--direct", path])
    outs = [no, fo, do] + ([qo] if have_qemu else [])
    ok = "ok" if all(x == outs[0] for x in outs) else "DIFF"
    def r(a, b):
        return a / max(b, 1e-6) if a == a else float("nan")
    print(f"{b:<10} {nt:8.3f} {qt:8.3f} {ft:8.3f} {dt:8.3f} {r(qt,nt):8.2f} {r(qt,ft):8.2f} {ok}")
