#!/usr/bin/env bash
# End-to-end fidelity check: native stdout/exit must match translator and --direct.
set -u
cd "$(dirname "$0")"
fail=0

expect() {
	local name="$1" bin="$2" want_out="$3" want_rc="$4"
	shift 4
	local out rc
	out=$("$@" "$bin" 2>/tmp/f86.err)
	rc=$?
	# runner reports via its own exit code; guest exit is that value
	if [[ "$out" != "$want_out" ]]; then
		echo "FAIL $name stdout"
		echo "  got:    $(printf %q "$out")"
		echo "  want:   $(printf %q "$want_out")"
		cat /tmp/f86.err >&2 || true
		fail=1
		return
	fi
	if [[ "$rc" -ne "$want_rc" ]]; then
		echo "FAIL $name rc=$rc want=$want_rc"
		cat /tmp/f86.err >&2 || true
		fail=1
		return
	fi
	echo "ok   $name"
}

run_pair() {
	local name="$1" bin="$2" want_out="$3" want_rc="$4"
	local nout nrc
	nout=$("$bin")
	nrc=$?
	if [[ "$nout" != "$want_out" || "$nrc" -ne "$want_rc" ]]; then
		echo "FAIL $name native changed (got rc=$nrc out=$(printf %q "$nout"))"
		fail=1
		return
	fi
	expect "$name translator" "$bin" "$want_out" "$want_rc" ./fast86
	expect "$name --direct"   "$bin" "$want_out" "$want_rc" ./fast86 --direct
}

run_pair tiny    ./benches/tiny    ""                 0
run_pair rec     ./benches/rec     $'11\n55'          0
run_pair regs    ./benches/regs    "regs-ok"          0
run_pair correct ./benches/correct "correct-ok"       0
run_pair vex     ./benches/vex     "vex-ok"           0
run_pair fib0    ./benches/fib0    "39088169"         0
run_pair fib     ./benches/fib     "39088169"         0
run_pair int     ./benches/int     "4922275915173715618" 0
run_pair mem     ./benches/mem     "1115683709"       0

# System-mode (no --direct): bare metal via COM1.
if [[ -f benches/syshello.bin ]]; then
	out=$(./fast86 --system --mem 128 benches/syshello.bin 2>/tmp/f86-sys.err) || true
	rc=$?
	if ! grep -q 'fast86-system-ok' /tmp/f86-sys.err || [[ "$rc" -ne 0 ]]; then
		echo "FAIL syshello --system rc=$rc"
		cat /tmp/f86-sys.err >&2 || true
		fail=1
	else
		echo "ok   syshello --system"
	fi
fi

# Kernel-half stack ops (push/pop/ret emulated via SIGSEGV): see benches/syspop.S.
if [[ -f benches/syspop.bin ]]; then
	out=$(./fast86 --system --mem 128 benches/syspop.bin 2>/tmp/f86-syspop.err) || true
	rc=$?
	if ! grep -q 'fast86-syspop-ok' /tmp/f86-syspop.err || [[ "$rc" -ne 0 ]]; then
		echo "FAIL syspop --system rc=$rc"
		grep -a 'syspop' /tmp/f86-syspop.err >&2 || true
		tail -5 /tmp/f86-syspop.err >&2 || true
		fail=1
	else
		echo "ok   syspop --system"
	fi
fi

if [[ -x /tmp/hello-static ]]; then
	out=$(./fast86 /tmp/hello-static 2>/tmp/f86-hello.err) || true
	rc=$?
	if [[ "$out" != $'hello from libc' || "$rc" -ne 0 ]]; then
		echo "FAIL hello translator out=$(printf %q "$out") rc=$rc"
		cat /tmp/f86-hello.err >&2 || true
		fail=1
	elif ! grep -q 'fast86: exit=0' /tmp/f86-hello.err; then
		echo "FAIL hello translator missing runner stats (escaped to raw exit?)"
		cat /tmp/f86-hello.err >&2 || true
		fail=1
	else
		echo "ok   hello translator"
	fi
	expect "hello --direct" /tmp/hello-static $'hello from libc' 0 ./fast86 --direct
fi

if [[ -x ./lenchk ]]; then
	for b in benches/int benches/fib benches/regs benches/correct; do
		objdump -dw "$b" > /tmp/f86.od
		if ./lenchk /tmp/f86.od | grep -q ', 0 mismatches'; then
			echo "ok   lenchk $b"
		else
			echo "FAIL lenchk $b"
			./lenchk /tmp/f86.od | tail -5
			fail=1
		fi
	done
	if [[ -f /tmp/hello.odw ]] || objdump -dw /tmp/hello-static > /tmp/hello.odw 2>/dev/null; then
		res=$(./lenchk /tmp/hello.odw)
		echo "$res" | tail -1
		if echo "$res" | grep -q ', 0 mismatches'; then
			echo "ok   lenchk hello-static"
		else
			echo "FAIL lenchk hello-static"
			echo "$res" | grep MISMATCH | head -10
			fail=1
		fi
	fi
fi

# Recovery boot capture (optional): when a real fast86 --system log exists,
# require Darwin + Recovery userspace + utilities, and no unrecovered panic.
SCRATCH="${SCRATCH:-/tmp/grok-goal-65064a9a1391/implementer}"
mkdir -p "$SCRATCH"
BOOTLOG="${BOOT_LOG:-$SCRATCH/boot-1.log}"
RECV_EFI=""
for p in /tmp/recvroot/System/Library/CoreServices/boot.efi \
         /tmp/recvol/System/Library/CoreServices/boot.efi; do
	if [[ -f "$p" ]]; then
		RECV_EFI="$p"
		break
	fi
done
if [[ -f "$BOOTLOG" ]]; then
	ok=1
	if ! grep -q 'Darwin Kernel Version' "$BOOTLOG"; then
		echo "FAIL recovery boot: missing Darwin kernel version"
		ok=0
	fi
	if ! grep -Eqi 'launchd|Recovery\.app|Setup Assistant|macOS Recovery' "$BOOTLOG"; then
		echo "FAIL recovery boot: missing Recovery/setup userspace"
		ok=0
	fi
	if ! grep -Eqi 'Disk Utility|Reinstall macOS|Restore from Time Machine|RecoveryOS|utilities' "$BOOTLOG"; then
		echo "FAIL recovery boot: missing Recovery utilities surface"
		ok=0
	fi
	if grep -q 'Darwin Kernel Version' "$BOOTLOG" && \
	   grep -E 'rsi "panic"|panic-msg@|Debugger' "$BOOTLOG" | tail -1 | grep -q panic; then
		# panic after Darwin with no later Recovery process is a fail
		if ! grep -Eqi 'Recovery\.app|macOS Recovery' "$BOOTLOG"; then
			echo "FAIL recovery boot: unrecovered panic after Darwin"
			ok=0
		fi
	fi
	if [[ "$ok" -eq 1 ]]; then
		echo "ok   recovery boot markers"
	else
		fail=1
	fi
elif [[ -z "$RECV_EFI" ]]; then
	echo "recovery assets missing" | tee "$SCRATCH/recovery-assets-skip.txt"
	echo "skip recovery boot markers (no assets)"
else
	echo "boot log not yet captured" | tee "$SCRATCH/recovery-assets-skip.txt"
	echo "skip recovery boot markers (no boot-1.log)"
fi

if [[ "$fail" -ne 0 ]]; then
	echo "FAILED"
	exit 1
fi
echo "all ok"
exit 0
