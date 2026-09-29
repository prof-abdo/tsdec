# TSDEC makefile for gcc and mingw
#
#   make            build tsdec
#   make test       build and run the self tests
#   make bench      build and run the throughput benchmark
#   make clean      remove build output
#
# The bitsliced CSA engine needs SSE2 on x86. On other targets set
# DVBCSA_WORD to uint32 (see src/dvbcsa/config.h).

CC          ?= gcc
# NB: do not call this LD, make already defines LD as "ld".
TSDEC_LINK  ?= $(CC)

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

obj/%.o : src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean test bench

all: tsdec

tsdec: $(OBJS)
	$(TSDEC_LINK) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# self test: the bitsliced engine must agree bit for bit with the scalar one
csa_selftest: tools/csa_selftest.c $(CSA_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# throughput comparison between the scalar and the bitsliced engine
bench_csa: tools/bench_csa.c $(CSA_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: csa_selftest tsdec
	./csa_selftest

bench: bench_csa
	./bench_csa

clean:
	rm -f tsdec tsdec.exe csa_selftest csa_selftest.exe bench_csa bench_csa.exe
	rm -rf obj
