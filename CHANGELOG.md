# Changelog

All notable changes to TSDEC are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[semantic versioning](https://semver.org/).

## [2.2.0] - 2026-09-29

### Added

- **A machine readable mode.** `tsdec --json` writes one JSON object per line on
  stdout and nothing else there: `progress` events while it works, then a single
  `result` event with the counts, the status code and a sentence saying what
  happened. This is what a front end should read. Parsing the human log was
  workable but it was never a contract, and it was not even reliably line
  separated, see below.
- `tsdec_status_text()` so the command line and `--json` describe a return code
  with the same words. A front end no longer has to invent its own wording.
- `percent` on every progress event, so a client does not have to recompute it.
- `total` on the result event, the number of packets in the input. A front end
  needs it to show how far a stopped run actually got: the packets written is
  the only honest number it has otherwise, and without a denominator the
  progress bar either sits at 100% or has to lie.

### Fixed

- **Log lines ran into each other.** `tsdec_log()` never terminated the line,
  so every message about an analysis, a pid survey or a summary came out as one
  long run of text. It was invisible on a terminal, where the eye reconnects
  the pieces, but a pipe got a single unparsable line, which is exactly how a
  front end reads it. The line ending is now added where it belongs.
- **Ctrl+C was ignored under Windows when the process was started in its own
  process group.** A parent that creates `CREATE_NEW_PROCESS_GROUP`, which is
  the normal way to send a control event to a child alone, also switches
  Ctrl+C off for that child. The signal handler is now installed after
  re-enabling it, so a stop from a parent behaves like a stop from a keyboard.
- **Throughput and ETA were wrong on multi core runs.** Both were measured
  with `clock()`, which counts processor time rather than elapsed time, so on
  every unix a run on eight threads was timed as if it had taken eight times
  longer than it did, understating the rate by the same factor. On Windows the
  CRT happens to return elapsed time, which is why this went unnoticed. The
  timing is now a real monotonic clock on both, and macOS uses the mach clock
  rather than a feature test macro, because defining one also hides
  `_SC_NPROCESSORS_ONLN` and breaks the CPU count.

### Changed

- `make test` now runs the cancellation test. It was built and then never
  executed, so the stop path had no coverage in the test target at all. The
  test also generates its own recording instead of expecting one to be lying
  around, and it is large enough that the stop lands mid run on a fast machine
  rather than after the work is already done.

## [2.1.0] - 2026-09-29

### Added

- **A stop path.** `tsdec_request_cancel()` asks a running job to stop from
  another thread, and Ctrl+C does the same instead of killing the process
  mid write. The 0.4.1 GUI had a stop button, so this is what a replacement
  front end needs to be honest about stopping.
- **A progress callback.** `tsdec_run()` takes a callback that fires a few
  times a second with packets done and input size, which is enough to show a
  real progress bar with a throughput figure and an estimate, rather than a
  bar that fills on a guess.
- `tsdec_job_t` replaces the long argument list. The old entry point stays as
  a wrapper, so nothing existing has to change.

Behaviour worth spelling out: on a stop the scout stops planning but the
workers drain what is already in the ring. Raising a shared stop flag would
have abandoned blocks that were planned and possibly decrypted but not yet
written, cutting the output at an arbitrary packet.

Verified by three new checks in the suite: cancelling at one and at eight
threads returns the cancelled status, leaves packet aligned output, and what
was written before the stop is byte identical to the plaintext.

## [2.0.0] - 2026-09-29

The first release under this repository. Based on TSDEC V0.4.1 by ganymede.

### Added

- **Bitsliced CSA engine.** The FFdecsa implementation already bundled with
  libdvbcsa was compiled but never called, so every packet went through the
  scalar table-lookup cipher on its own. Packets are now batched 128 at a time
  into SSE2 registers and the round function runs once per batch: **7.6x on the
  cipher, 18.5 to 141 MiB/s.**
- **Multi-threaded decryption** (`-t <n>`, default one worker per cpu). The work
  splits into a planning pass, which decides which logged control word applies
  to each packet, and an apply pass, which feeds runs of same-parity packets to
  the batch engine. Because a block's output offset is known as soon as it has
  been read, workers write to disjoint regions without locking.
  On 16 cores a 215 MiB recording goes from 1.66 s to 0.22 s.
- **`-p <pid>[,…]`** restrict processing to given PIDs, which makes a recording
  of a whole transponder usable when control words exist for only one service.
- **`-o -`** writes to stdout, so the output can be piped straight into a player
  or a transcoder.
- **`-P`** reports progress while decrypting.
- **`-r`** resyncs past packets whose sync byte is missing instead of aborting.
- **`-k`** refuses damaged control word checksums instead of repairing them.
- **Control word log parser** accepts logs with no parity column, recovering the
  parity from which half of the key carries a valid checksum, and accepts a key
  written as one 32 digit run.
- **Test suite.** `make test` cross checks the bitsliced engine against the
  scalar one bit for bit and against the published DVB test vectors.
  `tools/run_tests.sh` builds synthetic transport streams, encrypts them
  through tsdec's own constant control word path so the generated log genuinely
  matches the data, decrypts them again and compares packet by packet, and
  checks that every thread count produces identical output. 14 checks, run on
  Linux, macOS and Windows in CI.
- **Continuous integration** on Linux x86-64, macOS arm64 and Windows x86-64,
  and a release workflow that builds and attaches binaries for all three when a
  `v*` tag is pushed.

### Fixed

- **The control word log was reported as too short even on a successful match.**
  The cursor advanced past the last entry and was then checked against the
  end-of-log sentinel, so a log containing many control words failed part way
  through a recording.
- **Decrypted packets lost their adaptation field control and continuity
  counter.** Clearing the transport scrambling bits used a `0x3f` mask, which
  also wiped bits 4 and 5. Output is now correct in those fields, so a byte
  comparison against 0.4.1 differs on byte 4 of every scrambled packet while the
  payload is byte identical.
- **The sync probe could be wasted on unencrypted packets.** A PAT or PMT that
  was flagged as scrambled consumed the "try every control word" window, and
  probing then stopped until the parity flipped. PSI is no longer encrypted in
  the first place, which is what a real capture looks like.
- **`dvbcsa_bs_transpose128` read uninitialised registers** for packets shorter
  than eight bytes, transposing whatever happened to be on the stack.
- **`sscanf("%x")` wrote four bytes into an `unsigned char` array**, corrupting
  up to three bytes past each control word byte.
- **The tree did not build with a current gcc.** `config.h` carried a
  hand-rolled MSVC configuration that typedef'd `size_t` and the fixed width
  types by hand and defined `inline` away.
- **A control word log that runs out is no longer fatal.** tsdec reports the
  packet where the log stopped and continues with what it has.
- The Makefile resolves `CC` even when make supplies its own built-in default,
  detects the bitslice word size from the target, and rebuilds when a header
  changes rather than only when a source file does.

### Changed

- Blocked I/O: the input is read in 1 MiB blocks instead of one 188 byte
  `fread` per packet.
- Debug output goes through one logging function, and verbosity is now honoured
  on every platform rather than only on Windows.
- Statistics are reported at the end of a run: packets read, encrypted,
  decrypted, passed through, dropped, syncs and resyncs, corrupt packets and
  throughput.
- The Win32 GUI of 0.4.1 has no equivalent; the command line tool is the
  supported interface.
- The stale Visual Studio project files, which referenced sources that no
  longer exist, were removed.

[2.2.0]: https://github.com/prof-abdo/tsdec/releases/tag/v2.2.0
[2.1.0]: https://github.com/prof-abdo/tsdec/releases/tag/v2.1.0
[2.0.0]: https://github.com/prof-abdo/tsdec/releases/tag/v2.0.0
