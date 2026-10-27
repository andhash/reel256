CC      ?= cc
PYTHON  ?= python3
OS      := $(shell uname -s)
ARCH    := $(shell uname -m)

# The optimized code needs AES-NI (x86-64) or the ARMv8 crypto extension.
ifeq ($(ARCH),x86_64)
ARCHFLAGS ?= -march=native
else ifeq ($(OS)-$(ARCH),Darwin-arm64)
ARCHFLAGS ?= -mcpu=apple-m1
else
ARCHFLAGS ?= -mcpu=native
endif
CFLAGS  ?= -O3 -Wall -Wextra -std=c11
ALL     := $(CFLAGS) $(ARCHFLAGS) -Ic/include -Ic/opt -Itests

REF     := c/ref/reel_ref.c
OPT     := c/opt/reel_opt.c c/opt/aes.h
HDR     := c/include/reel.h

.PHONY: test test-c test-python test-go bench vectors clean

test: test-c test-python test-go

test-c: bin/test_ref bin/test_opt bin/test_cross $(if $(filter x86_64,$(ARCH)),bin/test_fake_neon)
	./bin/test_ref | tail -1
	./bin/test_opt | tail -1
	./bin/test_cross
	$(if $(filter x86_64,$(ARCH)),./bin/test_fake_neon | tail -1)

test-python:
	$(PYTHON) -I python/reel.py check test-vectors/reel256.json | tail -1

test-go:
	cd go && go test

bench: bin/bench
	./bin/bench

# regenerate the vectors from the Python reference (only when the spec changes)
vectors:
	$(PYTHON) -I python/reel.py generate > test-vectors/reel256.json
	$(PYTHON) -I tests/gen_header.py test-vectors/reel256.json > tests/vectors.h

bin/test_ref: tests/test_vectors.c tests/vectors.h $(REF) $(HDR)
	@mkdir -p bin
	$(CC) $(ALL) -o $@ tests/test_vectors.c $(REF)

bin/test_opt: tests/test_vectors.c tests/vectors.h $(OPT) $(HDR)
	@mkdir -p bin
	$(CC) $(ALL) -o $@ tests/test_vectors.c c/opt/reel_opt.c

# the ARM code path on x86, AESE and AESMC emulated with AES-NI (c/opt/aes.h)
bin/test_fake_neon: tests/test_vectors.c tests/vectors.h $(OPT) $(HDR)
	@mkdir -p bin
	$(CC) $(ALL) -DFAKE_NEON -o $@ tests/test_vectors.c c/opt/reel_opt.c

bin/test_cross: tests/test_cross.c $(REF) $(OPT) $(HDR)
	@mkdir -p bin
	$(CC) $(ALL) -Dreel256_encrypt=reel256_ref_encrypt -Dreel256_decrypt=reel256_ref_decrypt \
	  -c -o bin/reel_ref_renamed.o $(REF)
	$(CC) $(ALL) -o $@ tests/test_cross.c c/opt/reel_opt.c bin/reel_ref_renamed.o

bin/bench: bench/bench.c $(OPT) $(HDR)
	@mkdir -p bin
	$(CC) $(ALL) -o $@ bench/bench.c c/opt/reel_opt.c

clean:
	rm -rf bin
