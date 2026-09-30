# TSDEC makefile for gcc and mingw
#
#   make            build tsdec
#   make test       build and run the self tests
#   make bench      build and run the throughput benchmark
#   make clean      remove build output
#
# The bitsliced CSA engine needs SSE2 on x86. On other targets set
# DVBCSA_WORD to uint32 (see src/dvbcsa/config.h).

# make ships a built-in default CC = "cc", so "?=" would never take effect and
# "cc" is not a program on MSYS2. Only override it when the value really came
# from make itself, and never when the caller passed CC on the command line or
# in the environment.
ifeq ($(origin CC),default)
  CC := gcc
endif

# NB: do not call this LD, make already defines LD as "ld".
TSDEC_LINK ?= $(CC)

CFLAGS      ?= -O3
CFLAGS      += -Wall -W -Isrc
LDFLAGS     ?=
LDLIBS      ?= -lpthread

UNAME_S     := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Linux)
  LDLIBS := -lpthread
endif

# pick the bitslice word size for the host
ARCH := $(shell $(CC) -dumpmachine 2>/dev/null)
ifneq (,$(filter x86_64% i%86%,$(ARCH)))
  CFLAGS += -msse2
  TRANSPOSE_SRC = src/dvbcsa/dvbcsa_bs_transpose128.c
else
  CFLAGS += -DDVBCSA_USE_UINT32
  TRANSPOSE_SRC = src/dvbcsa/dvbcsa_bs_transpose32.c
endif

CORE_SRC = src/csa.c \
           src/tsdec_core.c \
           src/tsdec_main.c \
           src/dvbcsa/dvbcsa_algo.c \
           src/dvbcsa/dvbcsa_block.c \
           src/dvbcsa/dvbcsa_stream.c \
           src/dvbcsa/dvbcsa_bs_algo.c \
           src/dvbcsa/dvbcsa_bs_block.c \
           src/dvbcsa/dvbcsa_bs_key.c \
           src/dvbcsa/dvbcsa_bs_stream.c \
           src/dvbcsa/dvbcsa_bs_transpose.c \
           $(TRANSPOSE_SRC)

CSA_SRC  = src/csa.c \
           src/dvbcsa/dvbcsa_algo.c \
           src/dvbcsa/dvbcsa_block.c \
           src/dvbcsa/dvbcsa_stream.c \
           src/dvbcsa/dvbcsa_bs_algo.c \
           src/dvbcsa/dvbcsa_bs_block.c \
           src/dvbcsa/dvbcsa_bs_key.c \
           src/dvbcsa/dvbcsa_bs_stream.c \
           src/dvbcsa/dvbcsa_bs_transpose.c \
           $(TRANSPOSE_SRC)

OBJS := $(patsubst src/%.c,obj/%.o,$(subst src/dvbcsa/,src/dvbcsa/,$(CORE_SRC)))

# Every object depends on the headers, not just the matching source file.
# Without this, editing a header leaves stale objects behind and the next
# build quietly ships the old behaviour, which is how a version bump ended up
# reported as 1.0 after the constant had already been changed to 2.0.
HEADERS := $(wildcard src/*.h) $(wildcard src/dvbcsa/*.h)

obj/%.o : src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean test bench

all: tsdec

tsdec: $(OBJS)
	$(TSDEC_LINK) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# everything but the command line front end, for tools that supply their own
# main() and link against the core
LIB_SRC = $(filter-out src/tsdec_main.c,$(CORE_SRC))

# self test: the bitsliced engine must agree bit for bit with the scalar one
csa_selftest: tools/csa_selftest.c $(CSA_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# throughput comparison between the scalar and the bitsliced engine
bench_csa: tools/bench_csa.c $(CSA_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# drives the stop path the same way a front end would
cancel_test: tools/cancel_test.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# checks the residue rule: the last partial block of a payload is covered by
# the stream cipher alone, which is what a recording whose packets carry an
# adaptation field depends on
residue_test: tools/residue_test.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# checks the program tables, which are what turn a capture of a whole
# transponder into something a service can be picked out of
psi_test: tools/psi_test.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

PYTHON ?= python

# the cancellation test needs a recording big enough that one worker cannot
# finish it before the stop lands, so it builds its own on demand
test/cancel.enc.ts: tools/mk_ts.py tools/mk_test_pair.py tsdec
	mkdir -p test
	$(PYTHON) tools/mk_ts.py -o test/cancel.plain.ts -n 1500000 -s 7
	$(PYTHON) tools/mk_test_pair.py -i test/cancel.plain.ts \
		-o test/cancel.enc.ts -c test/cancel.cwl -t ./tsdec -w 20000 --quiet

# two services interleaved, which is what a transponder normally carries and
# what the program tables exist to make sense of
test/multi.ts: tools/mk_multi_ts.py tools/mk_test_pair.py tsdec
	mkdir -p test
	$(PYTHON) tools/mk_multi_ts.py -o test/multi.plain.ts \
		-c test/multi.cwl -n 20000 -s 5
	$(PYTHON) tools/mk_test_pair.py -i test/multi.plain.ts \
		-o test/multi.ts -c test/multi.enc.cwl -t ./tsdec -w 4000 --quiet
	rm -f test/multi.plain.ts

test: csa_selftest cancel_test residue_test psi_test tsdec \
	test/cancel.enc.ts test/multi.ts
	./csa_selftest
	./cancel_test
	./residue_test
	./psi_test

bench: bench_csa
	./bench_csa

clean:
	rm -f tsdec tsdec.exe csa_selftest csa_selftest.exe bench_csa bench_csa.exe
	rm -f residue_test residue_test.exe
	rm -f psi_test psi_test.exe
	rm -f cancel_test cancel_test.exe
	rm -rf obj
