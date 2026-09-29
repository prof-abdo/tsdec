# TSDEC — the transport stream offline decrypter

Decrypts recorded DVB transport stream files (`*.ts`) using control words
logged elsewhere, with the common scrambling algorithm.

Version 2.0. Based on TSDEC V0.4.1 by ganymede, which in turn grew out of
cwldec. The CSA engine and the FFdecsa bitslice implementation come from
libdvbcsa (Alexandre Becoulet), bundled under `src/dvbcsa`.

Releases: [CHANGELOG.md](CHANGELOG.md) ·
[latest release](https://github.com/prof-abdo/tsdec/releases/latest)

---

## What it does

One party with a valid subscription card records the control words (CWs) to a
log file. Someone else records the scrambled transport stream. Afterwards the
CWs and the stream can be combined offline to produce a clear recording.

This works for any DVB crypt system (Viaccess, Seca, BISS, Nagra, Conax, …)
because the system only governs what happens inside the smartcard. What the CAM
does with the control word to decrypt the transport stream is always the same.

Offline rather than card sharing: no IP address has to be revealed, no latency,
and no freezes when a control word arrives late. CWs can be logged by a card
server, a proxy or a card client.

Whether that is legal depends on where you are. It probably is not in most
European countries. It is released for educational purposes.

## Build

```sh
make              # builds ./tsdec (or tsdec.exe under mingw)
make test         # builds and runs the CSA self test
make bench        # scalar vs bitslice throughput comparison
make clean
```

Requires a C99 compiler. On x86 the bitslice engine is selected
automatically and needs SSE2, which every x86-64 CPU has. On other
architectures the Makefile falls back to a 32 bit wide engine.

For Windows, `mingw32-make` from MSYS2 works out of the box.

## Usage

```
tsdec -f <cwl> -i <in.ts> [-o <out.ts>] [options]
tsdec -a -i <in.ts> [options]
tsdec (-e|-d) <ccw> -i <in.ts> -o <out.ts>
```

### Decryption

| option | meaning |
|---|---|
| `-f <file>` | control word log (`.cwl`) to decrypt with |
| `-i <file>` | encrypted transport stream to read |
| `-o <file>` | where to write; `-` means stdout |
| `-e <ccw>` | encrypt with a constant control word |
| `-d <ccw>` | decrypt with a constant control word, e.g. BISS |

The constant control word is 16 hex bytes, an even key followed by an odd key:

```sh
tsdec -d "11 22 33 66 44 55 66 FF 01 23 45 67 89 AB CD EF" -i biss.ts -o clear.ts
```

The compact form works too, as a single 32 digit run:

```sh
tsdec -d 11223366445566FF0123456789ABCD00 -i biss.ts -o clear.ts
```

Either way both halves are checked against the DVB checksum in bytes 3 and 7,
and a mismatch is reported, since that usually means a typo in the log.

### Selection

| option | meaning |
|---|---|
| `-p <pid>[,…]` | only act on these PIDs, decimal or `0x` hex |

Useful when a recording holds a whole transponder with several services and you
only have control words for one of them.

```sh
tsdec -p 0x100,0x101 -f log.cwl -i rec.ts -o clear.ts
```

### Tuning

| option | meaning |
|---|---|
| `-t <n>` | decrypt with `n` worker threads; `1` disables threading |
| `-b <n>` | ignore a parity change shorter than `n` packets |
| `-r` | resync past packets whose sync byte is missing |
| `-k` | do not repair control word checksums, fail instead |

`-b` exists because of a real muxing artefact. Some transmissions flip the
transport scrambling parity back and forth for a while before settling:

```
VVVVVVAVVVVVVVAVVVVVVVAVVVVVVVAVVVVVVVAVVVVVVVAVVVVVVVAVVVVVVVVVVVVVVVV
00000000000010000001000000100000010000111111111111111111111111111
```

Advancing the control word on the first flip desynchronises everything that
follows. The default of 300 packets covers the common case; lower it if the
stream is very low bitrate and changes often, raise it if the parity flaps for
longer than that. `-b 0` turns the protection off.

### Output

| option | meaning |
|---|---|
| `-v <n>` | verbosity, 0 to 9, default 2 |
| `-q` | quiet, same as `-v 0` |
| `-P` | show progress while decrypting |
| `-h` | help |

Messages go to stderr, so `2>log.txt` captures them and stdout stays clean for
piping.

### Stopping

Ctrl+C asks the job to stop rather than killing it. Whatever was decrypted up
to that point is kept: the partial output stays a whole number of packets and
stays playable, so you can keep what finished rather than starting again.

```sh
tsdec -f log.cwl -i big-recording.ts -o clear.ts -P
# ... press Ctrl+C partway through
# clear.ts now holds everything that was processed before the stop
```

The stop is noticed between blocks, a block being about a megabyte, so it takes
effect within a fraction of a second rather than instantly. A stop in the
threaded path drains the blocks already in flight instead of abandoning them,
which is why the output never ends mid frame.

### Migrating from 1.0

Nothing you already scripted breaks. `-f`, `-i`, `-o`, `-e`, `-d`, `-a`, `-b`,
`-v` and `-h` keep their meaning, and 1.0 accepted `-n` without doing anything
with it, which 2.0 still tolerates.

What changed is the output, in two ways worth knowing about:

- 1.0 quit with "control word log too short" once the log ran out. 2.0 reports
  the packet where the log stopped and keeps going, which fixes recordings with
  long logs and makes a short log obvious instead of fatal.
- 1.0 cleared the transport scrambling bits with a mask that also wiped the
  adaptation field control and the continuity counter. Decrypted output is now
  correct in those bits too, so a byte comparison against 1.0 output will differ
  on the 4th byte of every scrambled packet while the payload is identical.

The Win32 GUI of 0.4.1 has no equivalent here; the command line tool is the
supported interface.

### Examples

```sh
tsdec -f log.cwl -i recording.ts -o clear.ts -P
tsdec -a -i recording.ts
tsdec -f log.cwl -i rec.ts -o - | vlc -
```

## How it works

Control words are read into memory first. Their parity must alternate 0, 1, 0,
1, … because the DVB standard says the sender flips the key half whenever the
parity changes, and the log records that sequence. Broken checksums in bytes 3
and 7 are repaired (disable with `-k`).

Then the transport stream is walked packet by packet. A packet with the payload
unit start indicator set begins an MPEG frame, and a frame starts with a header
that is only visible once the packet is correctly decrypted. When that header
turns up under some control word, the stream and the log are in sync.

From there every scrambled packet is decrypted with the current control word
until the parity changes, at which point the next logged control word takes
over. A parity change that lasts fewer than `-b` packets is ignored.

Unencrypted packets such as PAT, PMT, EPG and subtitles are passed through
untouched. The PAT and PMT matter: without them a player cannot tell which
streams are which.

If another payload unit start shows up while synced, the decryption is checked
again. If it fails (corrupt recording, missing or wrong control words, a
scrambled log) every control word is tried again. There will be a short freeze
in the video at that point, which is unavoidable.

## Performance

The original decrypted one packet at a time with a table lookup cipher and one
`fread` per 188 byte packet. Three things changed:

1. **Bitsliced CSA.** libdvbcsa's FFdecsa path transposes the bit planes of 128
   packets into SSE registers and runs the round function once for the whole
   batch. `make bench` measures it against the scalar path:

   ```
   scalar  :   488.20 ms      18.8 MiB/s    104875 pkt/s
   bitslice:    64.80 ms     141.7 MiB/s    790123 pkt/s
   speedup : 7.53x
   ```

   `make test` proves the two produce byte identical output, which is the only
   reason to trust the number.

2. **Blocked I/O.** The input is read in 1 MiB blocks instead of one packet at a
   time.

3. **Threads.** The work splits into two halves: a *scout* decides which control
   word applies to each packet, and *workers* run the bitsliced cipher on
   planned blocks. The scout is cheap once it is locked on, because it only
   reads packet headers, and it has to stay sequential since each control word
   depends on the previous one. Everything else runs in parallel, and because a
   block's output offset is known as soon as it has been read, the workers write
   to disjoint regions of the output file without locking.

On a 215 MiB recording, 16 core x86-64, minGW GCC 16:

| threads | time | throughput |
|--------:|-----:|-----------:|
| original (V0.4.1) | 11.99 s | failed to sync |
| 1 | 1.66 s | 129 MiB/s |
| 2 | 0.85 s | 254 MiB/s |
| 4 | 0.45 s | 475 MiB/s |
| 8 | 0.26 s | 828 MiB/s |
| 16 | 0.22 s | 988 MiB/s |

Roughly 55x over the original end to end, and the output is verified identical
at every thread count.

## Control word log format

Each line holds the parity followed by the eight key bytes, in hex:

```
0 00 00 00 00 00 00 00 00  # 12:00:00
1 11 22 33 66 44 55 66 FF  # 12:00:10
0 77 88 99 98 AA BB CC 31  # 12:00:20
1 FF FF FF FD FF FF FF FD  # 12:00:30
```

Everything after `#` is a comment, and the timestamp belongs there so logs from
different sources can be merged. Lines starting with `#`, `;`, `*` or `!` are
skipped. A log without the parity column is also accepted: the parity is
recovered from which half of the key carries a valid checksum.

Naming convention, which makes logs self describing:

```
090619-S192o-F11758h-C1702-I000A-P000000-DISCOVERY_CHANNEL.cwl
```

S satellite position, F frequency, C CAID, I service id, P provider id, and the
channel name last, without spaces or dashes.

## Testing

```sh
make test                      # the CSA engine against known vectors
tools/run_tests.sh ./tsdec     # full end to end suite
```

`tools/run_tests.sh` builds synthetic transport streams, encrypts them through
tsdec's own constant control word path so the generated log genuinely matches,
decrypts them again and compares the result against the original packet by
packet. It also checks that `-t 1`, `-t 2` and `-t 4` agree exactly, that a
stream without PSI works, that several elementary streams work, and that bad
arguments are rejected.

| tool | purpose |
|---|---|
| `tools/mk_ts.py` | synthetic plaintext transport stream |
| `tools/mk_test_pair.py` | runs it through the CSA engine, writes `.ts` + `.cwl` |
| `tools/verify.py` | compares a decrypted stream against the plaintext |
| `tools/csa_selftest.c` | bitsliced engine against the scalar one |
| `tools/bench_csa.c` | throughput of both engines |

## Known limitations

- One service per recording. Without reading the PAT and PMT, tsdec does not
  know which PIDs belong to which program, so a recording of several services
  interleaves control words and fails. `-p` sidesteps this by restricting the
  work to the PIDs you care about.
- A corrupt transport stream stops the run unless `-r` is given, in which case
  the damaged packets are copied through.
- A control word log that stops before the stream does leaves the remainder
  scrambled; there is nothing to decrypt it with.
- No GUI. V0.4.1 shipped a Win32 front end; the command line tool here is the
  supported interface.

## Licence

GPL v3 or later. libdvbcsa and FFdecsa are included under the same terms; see
the headers in `src/dvbcsa` for their copyright notices.
