#!/usr/bin/env bash
# End to end verification for tsdec.
#
#   1. builds a synthetic plaintext transport stream
#   2. encrypts it through tsdec's own constant-cw path, several control
#      words deep, so we get a matching .cwl
#   3. decrypts it again through the control word log path
#   4. compares the result against the original, packet for packet
#
# Usage: tools/run_tests.sh [path/to/tsdec]
#
# Everything inside this script uses POSIX paths (what the shell understands).
# The one place that matters is handing a path to a native tool -- python or a
# Windows tsdec build -- which needs cygpath, so that happens in n().

set -u

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$here/test"
mkdir -p "$work"

# Resolve the binary to an absolute path straight away. A relative one works
# for the shell but not for the python helper that later has to exec it, since
# that runs with its own idea of the current directory.
tsdec="${1:-$here/tsdec}"
if [ -x "$tsdec" ]; then
   tsdec="$(cd "$(dirname "$tsdec")" && pwd)/$(basename "$tsdec")"
elif [ -x "./$tsdec" ]; then
   tsdec="$PWD/$(basename "$tsdec")"
else
   echo "tsdec not found at $tsdec" >&2
   exit 1
fi

# Path handling is the fiddly part when running under MSYS2, because there are
# two kinds of program in play:
#
#   * MSYS programs (the "python" package from the MSYS repo) want POSIX paths
#     and treat "D:/x" as relative to the cwd
#   * native Windows programs (our mingw tsdec, or a python.org install) want
#     native paths
#
# Rather than guess, ask: try to open a known file with the interpreter and see
# which spelling it understands. Everything downstream then follows that.
python="${PYTHON:-python3}"
command -v "$python" >/dev/null 2>&1 || python=python

if "$python" -c 'import sys; open(sys.argv[1],"rb").close()' "$here/tools/mk_ts.py" 2>/dev/null; then
   py_uses_posix=1
else
   py_uses_posix=0
fi

# n() converts a POSIX path into one a native program accepts, and is a no-op
# for a path that is already native so that it is safe to apply twice.
if command -v cygpath >/dev/null 2>&1; then
   n() {
      case "$1" in
         [A-Za-z]:[\\/]*|*'\\'*) printf '%s' "$1" ;;
         *) cygpath -m "$1" ;;
      esac
   }
else
   n() { printf '%s' "$1"; }
fi

# py() runs a helper script; p() echoes a path in the spelling it wants.
if [ "$py_uses_posix" -eq 1 ]; then
   py() { "$python" "$1" "${@:2}"; }
   p()  { printf '%s' "$1"; }
else
   py() { "$python" "$(n "$1")" "${@:2}"; }
   p()  { n "$1"; }
fi

tsn() {
   "$tsdec" "$@"
}

pass=0
fail=0
ok()  { printf '  PASS  %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n' "$1"; fail=$((fail + 1)); }

# a control word pair whose checksums are valid, so nothing gets repaired
CCW="11 22 33 66 44 55 66 FF 01 23 45 67 89 AB CD EF"

# --- CSA engine -------------------------------------------------------------
echo "== CSA engine =="
selftest=""
for cand in "$here/csa_selftest" "$here/csa_selftest.exe"; do
   [ -x "$cand" ] && selftest="$cand" && break
done
if [ -n "$selftest" ]; then
   if "$selftest"; then ok "bitslice matches scalar, bit for bit"
   else no "bitslice matches scalar, bit for bit"; fi
else
   echo "  (csa_selftest not built, run: make test)"
fi

# --- synthetic round trips --------------------------------------------------
echo
echo "== control word log round trips =="

roundtrip() {
   local name="$1"; shift
   local out="$work/$name"

   py "$here/tools/mk_ts.py" -o "$(p "$out.plain.ts")" "$@" >/dev/null || return 1

   # mk_test_pair.py drives tsdec itself, and it is python handing over the
   # binary path, so that one has to be a native path either way
   py "$here/tools/mk_test_pair.py" -i "$(p "$out.plain.ts")" -o "$(p "$out.enc.ts")" \
      -c "$(p "$out.cwl")" -t "$(n "$tsdec")" -w 400 --quiet >/dev/null || return 1

   [ -s "$out.enc.ts" ] || return 1

   tsn -f "$(n "$out.cwl")" -i "$(n "$out.enc.ts")" -o "$(n "$out.out.ts")" -v 0 >/dev/null 2>&1

   py "$here/tools/verify.py" "$(p "$out.plain.ts")" "$(p "$out.out.ts")" 2>&1 | grep -q '^PASS'
}

roundtrip plain   -n 4000                       && ok "plain (11 control words)"     || no "plain"
roundtrip many    -n 8000                       && ok "many (20 control words)"     || no "many"
roundtrip nopsi   -n 8000 --no-psi              && ok "no PSI packets"              || no "no PSI packets"
roundtrip audio   -n 8000 --audio               && ok "video plus audio pid"        || no "video plus audio pid"
roundtrip onecw   -n 4000                       && ok "single control word"         || no "single control word"

# --- thread counts ----------------------------------------------------------
echo
echo "== threading =="
if [ -f "$work/many.enc.ts" ]; then
   base=""; same=1
   for t in 1 2 4; do
      tsn -f "$(n "$work/many.cwl")" -i "$(n "$work/many.enc.ts")" \
          -o "$(n "$work/many.t$t.ts")" -t "$t" -v 0 >/dev/null 2>&1
      h=$(sha256sum "$work/many.t$t.ts" 2>/dev/null | cut -d' ' -f1)
      if [ -z "$base" ]; then base="$h"; elif [ "$h" != "$base" ]; then same=0; fi
   done
   [ "$same" -eq 1 ] && ok "-t 1, -t 2 and -t 4 give identical output" \
                     || no "-t 1, -t 2 and -t 4 give identical output"

   if py "$here/tools/verify.py" "$(p "$work/many.plain.ts")" "$(p "$work/many.t4.ts")" 2>&1 | grep -q '^PASS'; then
      ok "threaded output matches the plaintext"
   else
      no "threaded output matches the plaintext"
   fi
fi

# --- constant control word --------------------------------------------------
echo
echo "== constant control word =="
if [ -f "$work/plain.plain.ts" ]; then
   # mark the packets the way a front end card records them: scrambling bits
   # set, payload not actually encrypted yet
   "$python" - "$(p "$work/plain.plain.ts")" "$(p "$work/ccw.in.ts")" <<'PYEOF'
import sys
d = bytearray(open(sys.argv[1], 'rb').read())
for i in range(0, len(d), 188):
    if ((d[i + 3] >> 4) & 3) == 1:
        d[i + 3] = (d[i + 3] & 0x3f) | 0x80
open(sys.argv[2], 'wb').write(d)
PYEOF
   tsn -e "$CCW" -i "$(n "$work/ccw.in.ts")" -o "$(n "$work/ccw.enc.ts")" -v 0 >/dev/null 2>&1
   tsn -d "$CCW" -i "$(n "$work/ccw.enc.ts")" -o "$(n "$work/ccw.out.ts")" -v 0 >/dev/null 2>&1
   if py "$here/tools/verify.py" "$(p "$work/ccw.in.ts")" "$(p "$work/ccw.out.ts")" 2>&1 | grep -q '^PASS'; then
      ok "encrypt then decrypt with a constant cw"
   else
      no "encrypt then decrypt with a constant cw"
   fi
fi

# --- analysis and pid filter ------------------------------------------------
echo
echo "== analysis =="
if [ -f "$work/many.enc.ts" ]; then
   tsn -a -i "$(n "$work/many.enc.ts")" -v 1 2>&1 | grep -q 'pid survey' \
      && ok "-a prints a pid survey" || no "-a prints a pid survey"

   tsn -f "$(n "$work/many.cwl")" -i "$(n "$work/many.enc.ts")" \
       -o "$(n "$work/filtered.ts")" -p 0x100 -v 0 >/dev/null 2>&1 \
      && ok "-p accepts a pid filter" || no "-p accepts a pid filter"
fi

# --- error handling ---------------------------------------------------------
echo
echo "== error handling =="
tsn -i "$(n "$work/does-not-exist.ts")" -o "$(n "$work/x.ts")" -v 0 >/dev/null 2>&1
[ $? -ne 0 ] && ok "missing input is rejected" || no "missing input is rejected"

tsn -f "$(n "$work/does-not-exist.cwl")" -i "$(n "$work/plain.plain.ts")" \
    -o "$(n "$work/x.ts")" -v 0 >/dev/null 2>&1
[ $? -ne 0 ] && ok "missing cwl is rejected" || no "missing cwl is rejected"

tsn -f "$(n "$work/plain.cwl")" -i "$(n "$work/plain.plain.ts")" >/dev/null 2>&1
[ $? -ne 0 ] && ok "missing -o is a usage error" || no "missing -o is a usage error"

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
