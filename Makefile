# SPDX-License-Identifier: GPL-2.0
#
#   make            build build/tsn-switch and build/tsn_xdp.bpf.o
#   make test       run the veth integration tests (needs root)
#   make clean

CC      ?= gcc
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -pthread
LDLIBS  += $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz) -pthread
CFLAGS  += $(shell pkg-config --cflags libbpf 2>/dev/null)

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall
ifneq ($(MULTIARCH),)
BPF_CFLAGS += -I/usr/include/$(MULTIARCH)
endif

BUILD := build
SRCS  := $(wildcard src/*.c)
OBJS  := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
HDRS  := $(wildcard src/*.h)

all: $(BUILD)/tsn-switch $(BUILD)/tsn_xdp.bpf.o

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tsn-switch: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/tsn_xdp.bpf.o: bpf/tsn_xdp.bpf.c src/common.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

test: all
	sudo ./tests/run_tests.sh

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
