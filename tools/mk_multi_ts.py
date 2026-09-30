#!/usr/bin/env python3
"""Build a plaintext recording that carries two services, like a transponder.

A satellite transponder normally does not carry one programme, it carries
several, each with its own elementary streams and its own control words. A
capture of one is the normal case rather than the special one, and it is the
case a decoder cannot handle without reading the program tables: the pids of
the two services are interleaved through the file, and so are their control
words, so picking the wrong service gives output that decrypts cleanly and is
not the programme that was asked for.

So this writes what that looks like:

  pid 0x0000   the pat, naming program 1 on pmt pid 0x50, program 2 on 0x60
  pid 0x0050   the pmt for program 1: mpeg-2 video on 0x100, audio on 0x101
  pid 0x0060   the pmt for program 2: h.264 video on 0x200, no audio
  pid 0x0100   program 1 video
  pid 0x0101   program 1 audio
  pid 0x0200   program 2 video

The tables are in the clear, which is what a real capture looks like: program
specific information is a control structure and is not scrambled even when the
elementary streams beside it are.

This produces the plaintext and the control word log. The encryption is left to
tools/mk_test_pair.py, which already knows how to alternate the key half and
which pids to leave alone, so there is one implementation of that rather than
two that can drift apart.

    mk_multi_ts.py -o out.plain.ts -c out.cwl -n 40000
"""

import argparse
import random
import struct
import sys

PCKTSIZE = 188

PAT_PID = 0x0000
PMT1_PID = 0x0050
PMT2_PID = 0x0060
P1_VIDEO = 0x0100
P1_AUDIO = 0x0101
P2_VIDEO = 0x0200

# the pids that stay in the clear, matching what mk_test_pair.py leaves alone
PSI_PIDS = (PAT_PID, PMT1_PID, PMT2_PID)

_crc_table = None


def mpeg_crc(data):
    """The crc the transport stream uses, which is not the crc32 a library
    hands out: same polynomial, no inversion, no final xor."""
    global _crc_table
    if _crc_table is None:
        table = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                c = (((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF) if c & 0x80000000 \
                    else ((c << 1) & 0xFFFFFFFF)
            table.append(c)
        _crc_table = table
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _crc_table[((crc >> 24) ^ b) & 0xFF]
    return crc


def section(body):
    return body + struct.pack(">I", mpeg_crc(body))


def make_pat():
    # two programs: 1 on pmt pid 0x50 and 2 on pmt pid 0x60
    body = bytes([0x00, 0xB0, 0x11, 0x00, 0x01, 0xC1, 0x00, 0x00,
                  0x00, 0x01, 0xE0, 0x50,
                  0x00, 0x02, 0xE0, 0x60])
    return section(body)


def make_pmt(program, pcr, streams):
    """streams is a list of (stream_type, pid)."""
    body = bytes([0x02, 0xB0, 0x00, (program >> 8) & 0xFF, program & 0xFF,
                  0xC1, 0x00, 0x00,
                  0xE0 | ((pcr >> 8) & 0x1F), pcr & 0xFF,
                  0xF0, 0x00])
    for stype, pid in streams:
        body += bytes([stype, 0xE0 | ((pid >> 8) & 0x1F), pid & 0xFF,
                       0xF0, 0x00])
    # the section length counts everything after the first two bytes, crc in
    length = len(body) - 3 + 4
    body = body[:1] + bytes([0xB0 | ((length >> 8) & 0x0F), length & 0xFF]) \
        + body[3:]
    return section(body)


def ts_packet(pid, pusi, payload, cc):
    pkt = bytearray(4)
    pkt[0] = 0x47
    pkt[1] = ((1 if pusi else 0) << 6) | ((pid >> 8) & 0x3F)
    pkt[2] = pid & 0xFF
    pkt[3] = 0x10 | (cc & 0x0F)
    pkt += payload
    while len(pkt) < PCKTSIZE:
        pkt.append(0xFF)
    return bytes(pkt)


def psi_packet(pid, cc, sect):
    # a pusi packet starts its payload with a pointer field; zero here because
    # the section starts immediately, but the byte is still there and a reader
    # that skips it lands one byte into the section
    return ts_packet(pid, 1, b"\x00" + sect, cc)


def make_pes(stream_id, payload):
    hdr = bytes([0x00, 0x00, 0x01, stream_id])
    length = b"\x00\x00" if stream_id == 0xE0 else struct.pack(">H",
                                                                6 + len(payload))
    return hdr + length + bytes([0x80, 0x00, 0x00]) + payload


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", required=True, help="plaintext ts to write")
    ap.add_argument("-c", "--cwl", required=True, help="control word log to write")
    ap.add_argument("-n", "--packets", type=int, default=40000)
    ap.add_argument("-s", "--seed", type=int, default=1)
    ap.add_argument("-w", "--cwlen", type=int, default=4000)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    pmt1 = make_pmt(1, P1_VIDEO, [(0x02, P1_VIDEO), (0x03, P1_AUDIO)])
    pmt2 = make_pmt(2, P2_VIDEO, [(0x1B, P2_VIDEO)])

    cc = {PAT_PID: 0, PMT1_PID: 0, PMT2_PID: 0, P1_VIDEO: 0, P1_AUDIO: 0,
          P2_VIDEO: 0}
    since_pusi = {P1_VIDEO: 99, P1_AUDIO: 99, P2_VIDEO: 99}
    chunk = PCKTSIZE - 4

    # one control word per cwlen packets, alternating parity, which is what a
    # real stream does and what the decoder follows
    keys = [(k % 2, bytes(rng.randrange(256) for _ in range(8)))
            for k in range(max(2, (args.packets // args.cwlen) + 2))]

    with open(args.cwl, "w") as f:
        f.write("# two services, generated by tools/mk_multi_ts.py\n")
        f.write("# seed=%d cwlen=%d packets=%d\n"
                % (args.seed, args.cwlen, args.packets))
        for k, (par, key) in enumerate(keys):
            f.write("%d %s   # packet %d\n"
                    % (par, " ".join("%02X" % b for b in key), k * args.cwlen))

    written = 0
    with open(args.out, "wb") as out:
        index = 0
        while written < args.packets:
            if index % 200 == 0:
                out.write(psi_packet(PAT_PID, cc[PAT_PID], make_pat()))
                cc[PAT_PID] = (cc[PAT_PID] + 1) & 0xF
                out.write(psi_packet(PMT1_PID, cc[PMT1_PID], pmt1))
                cc[PMT1_PID] = (cc[PMT1_PID] + 1) & 0xF
                out.write(psi_packet(PMT2_PID, cc[PMT2_PID], pmt2))
                cc[PMT2_PID] = (cc[PMT2_PID] + 1) & 0xF
                written += 3
                index += 3
                continue

            # interleave the two services the way a multiplexer does
            if index % 7 in (2, 5):
                pid, stream_id = P2_VIDEO, 0xE0
            elif index % 3 == 0:
                pid, stream_id = P1_AUDIO, 0xC0
            else:
                pid, stream_id = P1_VIDEO, 0xE0

            if since_pusi[pid] >= 8:
                body = bytes(rng.randrange(256)
                             for _ in range(rng.randrange(600, 2000)))
                pes = make_pes(stream_id, body)
                head, rest = pes[:8], pes[8:]
                parts = [head]
                while rest:
                    parts.append(rest[:chunk])
                    rest = rest[chunk:]
                pusi = True
            else:
                parts = [bytes(rng.randrange(256) for _ in range(chunk))]
                pusi = False

            for i, part in enumerate(parts):
                if written >= args.packets:
                    break
                out.write(ts_packet(pid, pusi and i == 0, part, cc[pid]))
                cc[pid] = (cc[pid] + 1) & 0xF
                written += 1

            since_pusi[pid] = 0 if pusi else since_pusi[pid] + 1
            index += 1

    print("wrote %s (%d packets) and %s, %d pids in the clear"
          % (args.out, written, args.cwl, len(PSI_PIDS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
