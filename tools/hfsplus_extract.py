#!/usr/bin/env python3
"""Minimal HFS+ catalog walker — extract named files from an Apple HFS+ volume."""
from __future__ import annotations

import argparse
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

BE16 = ">H"
BE32 = ">I"
BE64 = ">Q"


def u16(b: bytes, o: int = 0) -> int:
    return struct.unpack_from(BE16, b, o)[0]


def u32(b: bytes, o: int = 0) -> int:
    return struct.unpack_from(BE32, b, o)[0]


def u64(b: bytes, o: int = 0) -> int:
    return struct.unpack_from(BE64, b, o)[0]


class HFSPlus:
    def __init__(self, fp, part_off: int):
        self.fp = fp
        self.part_off = part_off
        fp.seek(part_off + 1024)
        vh = fp.read(512)
        if vh[:2] not in (b"H+", b"HX"):
            raise SystemExit(f"not HFS+ at {part_off}: {vh[:8]!r}")
        self.block = u32(vh, 40)
        self.total = u32(vh, 44)
        # catalog fork at 0x110
        self.cat_size = u64(vh, 0x110)
        self.cat_extents = [
            (u32(vh, 0x120 + i * 8), u32(vh, 0x124 + i * 8)) for i in range(8)
        ]
        hdr = self.read_fork(self.cat_extents, 0, 512)
        self.node_size = u16(hdr, 32)
        self.root_node = u32(hdr, 16)
        self.leaf_records = u32(hdr, 20)
        self.first_leaf = u32(hdr, 24)
        self.last_leaf = u32(hdr, 28)
        print(
            f"HFS+ block={self.block} catalog={self.cat_size} "
            f"node={self.node_size} root={self.root_node} "
            f"firstLeaf={self.first_leaf} leafRecs={self.leaf_records}",
            file=sys.stderr,
        )

    def read_abs(self, off: int, n: int) -> bytes:
        self.fp.seek(self.part_off + off)
        return self.fp.read(n)

    def read_fork(self, extents, off: int, n: int) -> bytes:
        out = bytearray()
        remain = n
        cur = off
        for start, count in extents:
            if count == 0:
                continue
            span = count * self.block
            if cur >= span:
                cur -= span
                continue
            take = min(remain, span - cur)
            out += self.read_abs(start * self.block + cur, take)
            remain -= take
            cur = 0
            if remain == 0:
                break
        return bytes(out)

    def node(self, idx: int) -> bytes:
        return self.read_fork(self.cat_extents, idx * self.node_size, self.node_size)

    def walk_leaves(self):
        n = self.first_leaf
        seen = 0
        while n and seen < 200000:
            node = self.node(n)
            kind = node[8]
            nrec = u16(node, 10)
            flink = u32(node, 0)
            offs = [
                u16(node, self.node_size - 2 * (i + 1)) for i in range(nrec)
            ]
            for o in offs:
                if o + 8 < self.node_size:
                    yield node[o:]
            if kind != 0xFF:  # not a leaf
                break
            if flink == n:
                break
            n = flink
            seen += 1

    @staticmethod
    def parse_key(rec: bytes) -> Tuple[int, str, int]:
        klen = u16(rec, 0)
        parent = u32(rec, 2)
        nlen = u16(rec, 6)
        name = rec[8 : 8 + nlen * 2].decode("utf-16be", "replace")
        return parent, name, 2 + klen

    def files(self):
        for rec in self.walk_leaves():
            if len(rec) < 10:
                continue
            parent, name, rec_off = self.parse_key(rec)
            if rec_off + 2 > len(rec):
                continue
            rtype = u16(rec, rec_off)
            body = rec[rec_off:]
            if rtype == 2:  # file
                cnid = u32(body, 8) if len(body) >= 12 else 0
                # HFSPlusForkData dataFork starts at 88 in file record
                if len(body) < 88 + 80:
                    continue
                dsize = u64(body, 88)
                dext = [
                    (u32(body, 88 + 16 + i * 8), u32(body, 88 + 20 + i * 8))
                    for i in range(8)
                ]
                yield parent, name, cnid, dsize, dext, "file"
            elif rtype == 1:  # folder
                cnid = u32(body, 8) if len(body) >= 12 else 0
                yield parent, name, cnid, 0, [], "dir"


def extract(img: str, part_off: int, want: List[str], dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    with open(img, "rb") as fp:
        vol = HFSPlus(fp, part_off)
        # first pass: cnid map
        folders: Dict[int, Tuple[int, str]] = {2: (0, "")}  # root
        files = []
        for parent, name, cnid, size, ext, kind in vol.files():
            if kind == "dir":
                folders[cnid] = (parent, name)
            else:
                files.append((parent, name, cnid, size, ext))

        def path_of(parent: int, name: str) -> str:
            parts = [name]
            seen = set()
            p = parent
            while p and p not in seen:
                seen.add(p)
                if p not in folders:
                    break
                pp, pn = folders[p]
                if pn:
                    parts.append(pn)
                p = pp
            return "/".join(reversed(parts))

        want_l = [w.lower().replace("\\", "/") for w in want]
        extracted = 0
        listed = 0
        for parent, name, cnid, size, ext in files:
            full = path_of(parent, name)
            listed += 1
            fl = full.lower()
            hit = any(
                fl == w or fl.endswith("/" + w) or w in fl for w in want_l
            )
            if listed <= 30 or hit:
                print(f"  {kind_line(size)} {full}", file=sys.stderr)
            if not hit:
                continue
            data = vol.read_fork(ext, 0, size) if size else b""
            # Catalog names are untrusted: keep the tree readable but
            # refuse anything that would leave --dest (../ or absolute).
            rel = full
            parts = [c for c in rel.split("/") if c not in ("", ".")]
            if any(c == ".." for c in parts) or not parts:
                print(f"skipping unsafe name {rel!r}", file=sys.stderr)
                continue
            outp = os.path.join(dest, *parts)
            dest_real = os.path.realpath(dest)
            if os.path.commonpath([dest_real, os.path.realpath(outp)]) != dest_real:
                print(f"skipping unsafe name {rel!r}", file=sys.stderr)
                continue
            os.makedirs(os.path.dirname(outp), exist_ok=True)
            with open(outp, "wb") as o:
                o.write(data)
            print(f"extracted {rel} ({len(data)} bytes) -> {outp}")
            extracted += 1
        print(f"catalog files={listed} extracted={extracted}", file=sys.stderr)


def kind_line(size: int) -> str:
    if size > 1 << 20:
        return f"{size/1048576:8.1f}M"
    return f"{size:8d}B"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--part-lba", type=int, default=409640)
    ap.add_argument("--dest", default="/tmp/recovery")
    ap.add_argument(
        "--want",
        nargs="*",
        default=[
            "boot.efi",
            "kernel",
            "prelinkedkernel",
            "kernelcache",
            "immutablekernel",
            "Prelinkedkernel",
            "com.apple.Boot.plist",
            "PlatformSupport.plist",
            "SystemVersion.plist",
        ],
    )
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()
    part_off = args.part_lba * 512
    if args.list_only:
        with open(args.image, "rb") as fp:
            vol = HFSPlus(fp, part_off)
            n = 0
            for parent, name, cnid, size, ext, kind in vol.files():
                if kind == "file":
                    print(f"{size:12d}  {name}")
                    n += 1
            print(f"# {n} files", file=sys.stderr)
        return
    extract(args.image, part_off, args.want, args.dest)


if __name__ == "__main__":
    main()
