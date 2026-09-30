#!/usr/bin/env python3
"""Generate a synthetic plaintext DVB transport stream for tsdec testing.

The output is genuine plaintext with no scrambling bits set. Feed it to
tools/mk_test_pair.py, which runs it through tsdec's own CSA engine to produce
a real encrypted stream plus the matching control word log.

The stream carries:
  - a PAT and a PMT, both unencrypted, like a real capture
  - one video PID, and optionally an audio PID
  - PES units split across many TS packets, with PUSI marking each start

Nothing here is encrypted: producing an encrypted stream and a control word
log that genuinely correspond is the job of mk_test_pair.py.
"""

import argparse
import random
import struct

PCKTSIZE = 188
PAT_PID = 0x0000
# The pat has to point at the pid the pmt is actually sent on, or a reader
# that trusts it will listen to a pid nobody is using.
PMT_PID = 0x0050
VIDEO_PID = 0x0100
AUDIO_PID = 0x0101

_crc_table = None


def mpeg_crc(data):
    global _crc_table
    if _crc_table is None:
        table = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                if c & 0x80000000:
                    c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
                else:
                    c = (c << 1) & 0xFFFFFFFF
            table.append(c)
        _crc_table = table
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _crc_table[((crc >> 24) ^ b) & 0xFF]
    return crc


def ts_packet(pid, pusi, payload, cc):
    """One 188 byte packet, adaptation field control = payload only, no
    scrambling. That is what a decrypted stream looks like."""
    pkt = bytearray(4)
    pkt[0] = 0x47
    pkt[1] = ((1 if pusi else 0) << 6) | ((pid >> 8) & 0x3F)
    pkt[2] = pid & 0xFF
    pkt[3] = 0x10 | (cc & 0x0F)          # AFC payload only, TSC = not scrambled
    pkt += payload
    while len(pkt) < PCKTSIZE:
        pkt.append(0xFF)
    return bytes(pkt)


def psi_packet(pid, cc, section):
    """A pusi packet carrying one whole section.

    A pusi packet starts its payload with a pointer field saying how far in the
    new section begins. Here it is zero, because the section does start
    immediately, but the byte is still there, and a reader that skips it lands
    one byte into the section and then rejects it on the checksum.
    """
    return ts_packet(pid, 1, b"\x00" + section, cc)


def make_pat():
    # table_id 0x00, section_syntax_indicator 1 with the top of the length,
    # section_length 13, transport_stream_id, version/current_next and the
    # section numbers, then one program mapping 1 onto pmt pid 0x50, then the
    # crc over all of it
    body = bytes([0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00,
                  0x00, 0x01, 0xE0, 0x50])
    return body + struct.pack(">I", mpeg_crc(body))


def make_pmt():
    # program 1, version/current_next, section 0, pcr pid 0x50, program info
    # length 0, no scrambling flag, then two elementary streams: mpeg-2 video on
    # 0x100 and mpeg audio on 0x101
    # table_id 0x02 for a pmt, section_syntax_indicator 1 with the top of the
    # length, section_length 23, program_number 1, version/current_next and
    # the section numbers, pcr pid 0x50, program_info_length 0 and no
    # scrambling flag, then two elementary streams: mpeg-2 video on 0x100 and
    # mpeg audio on 0x101, then the crc over all of it
    body = bytes([0x02, 0xB0, 0x17, 0x00, 0x01, 0xC1, 0x00, 0x00,
                  0xE0, 0x50, 0xF0, 0x00,
                  0x02, 0xE1, 0x00, 0xF0, 0x00,
                  0x03, 0xE1, 0x01, 0xF0, 0x00])
    return body + struct.pack(">I", mpeg_crc(body))


def make_pes(stream_id, payload):
    hdr = bytes([0x00, 0x00, 0x01, stream_id])
    length = b"\x00\x00" if stream_id == 0xE0 else struct.pack(">H", 6 + len(payload))
    return hdr + length + bytes([0x80, 0x00, 0x00]) + payload


def build(rng, total_packets, with_audio, psi_every):
    packets = []
    cc = {VIDEO_PID: 0, AUDIO_PID: 0, PAT_PID: 0, PMT_PID: 0}
    since_pusi = {VIDEO_PID: 99, AUDIO_PID: 99}
    chunk = PCKTSIZE - 4

    while len(packets) < total_packets:
        index = len(packets)

        # unencrypted PSI, exactly like a real recording
        if psi_every and index % psi_every == 0:
            packets.append(psi_packet(PAT_PID, cc[PAT_PID], make_pat()))
            cc[PAT_PID] = (cc[PAT_PID] + 1) & 0xF
            continue
        if psi_every and index % psi_every == psi_every // 2:
            packets.append(psi_packet(PMT_PID, cc[PMT_PID], make_pmt()))
            cc[PMT_PID] = (cc[PMT_PID] + 1) & 0xF
            continue

        pid = AUDIO_PID if (with_audio and index % 3 == 0) else VIDEO_PID

        if since_pusi[pid] >= 6:
            stream_id = 0xE0 if pid == VIDEO_PID else 0xC0
            body = bytes(rng.randrange(256) for _ in range(rng.randrange(600, 2400)))
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
            if len(packets) >= total_packets:
                break
            packets.append(ts_packet(pid, pusi and i == 0, part, cc[pid]))
            cc[pid] = (cc[pid] + 1) & 0x0F
            since_pusi[pid] += 1

        if pusi:
            since_pusi[pid] = 0

    return packets[:total_packets]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("-n", "--packets", type=int, default=20000)
    ap.add_argument("-s", "--seed", type=int, default=1234)
    ap.add_argument("--audio", action="store_true", help="add a second, audio PID")
    ap.add_argument("--no-psi", action="store_true", help="omit PAT/PMT packets")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    packets = build(rng, args.packets, args.audio, 0 if args.no_psi else 100)

    with open(args.out, "wb") as f:
        f.write(b"".join(packets))

    print("wrote %s: %d packets (%d bytes)"
          % (args.out, len(packets), len(packets) * PCKTSIZE))


if __name__ == "__main__":
    main()
