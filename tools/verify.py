#!/usr/bin/env python3
"""Verify a decrypted TS against the known plaintext.

Compares packet payloads (not the transport scrambling control bits, which
tsdec deliberately clears after decrypting) and reports continuity/PES sanity.
"""

import argparse
import hashlib
import sys

PCKTSIZE = 188


def payload_sha(data):
    h = hashlib.sha256()
    for i in range(0, len(data), PCKTSIZE):
        p = data[i:i + PCKTSIZE]
        if len(p) < PCKTSIZE:
            break
        p = bytearray(p)
        p[3] &= 0xC0          # keep TEI/PUSI/TP, drop TSC+AFC+CC
        p[3] &= 0x3F | 0xC0
        h.update(bytes(p))
    return h.hexdigest()


def pes_stats(data):
    """Count packets with a PUSI-set PES start code, plus sync byte errors."""
    pusi_pes = 0
    sync_err = 0
    for i in range(0, len(data), PCKTSIZE):
        p = data[i:i + PCKTSIZE]
        if len(p) < PCKTSIZE:
            break
        if p[0] != 0x47:
            sync_err += 1
            continue
        pusi = (p[1] >> 6) & 1
        afc = (p[3] >> 4) & 3
        off = 4
        if afc in (2, 3):
            off = 5 + p[4]
        if pusi and off + 3 <= PCKTSIZE and p[off:off + 3] == b"\x00\x00\x01":
            pusi_pes += 1
    return pusi_pes, sync_err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("plain")
    ap.add_argument("decrypted")
    ap.add_argument("--expect-pes", type=int, default=None,
                    help="minimum number of valid PES starts expected")
    args = ap.parse_args()

    a = open(args.plain, "rb").read()
    b = open(args.decrypted, "rb").read()

    if len(a) != len(b):
        print("FAIL: size mismatch %d != %d" % (len(a), len(b)))
        sys.exit(1)

    bad = 0
    first = -1
    for i in range(0, len(a), PCKTSIZE):
        pa = bytearray(a[i:i + PCKTSIZE])
        pb = bytearray(b[i:i + PCKTSIZE])
        # TSC (0xC0) is cleared by the decoder; everything else must match
        pa[3] &= 0x3F
        pb[3] &= 0x3F
        if pa != pb:
            bad += 1
            if first < 0:
                first = i // PCKTSIZE

    npk = len(a) // PCKTSIZE
    pes, syncerr = pes_stats(b)

    if bad == 0:
        print("PASS: %d packets identical (except TSC bits)" % npk)
        print("      payload sha=%s" % payload_sha(b)[:32])
        print("      PES starts=%d  sync errors=%d" % (pes, syncerr))
        if args.expect_pes is not None and pes < args.expect_pes:
            print("WARN: only %d PES starts, expected >= %d" % (pes, args.expect_pes))
        sys.exit(0)

    print("FAIL: %d/%d packets differ, first at packet %d" % (bad, npk, first))
    i = first * PCKTSIZE
    print("  plain: %s" % a[i:i + 16].hex())
    print("  decry: %s" % b[i:i + 16].hex())
    sys.exit(1)


if __name__ == "__main__":
    main()
