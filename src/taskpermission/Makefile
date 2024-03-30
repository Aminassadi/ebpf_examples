# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
APP = taskpermission

DEPS := ../.deps
BIN := ../.bin
OBJ = ./obj
SKELETON = skeleton
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL_OUTPUT ?= $(abspath $(DEPS)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/riscv64/riscv/')

LIBBPF_OBJ := $(abspath $(DEPS)/libbpf.a)
VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(DEPS) -I$(SKELETON) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) #dir extracts the directory of the given path
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)


.PHONY: all
all: $(BIN)/$(APP)

.PHONY: clean
clean:
	$(Q)rm -rf $(BIN)/$(APP) $(SKELETON) $(OBJ)

$(BIN):
	$(Q)mkdir -p $@

$(SKELETON):
	$(Q)mkdir -p $@

$(OBJ):
	$(Q)mkdir -p $@

# Build BPF code
$(OBJ)/$(APP).bpf.o: $(APP).bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -fstack-protector -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(APP).bpf.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(SKELETON)/$(APP).skel.h: $(OBJ)/$(APP).bpf.o $(SKELETON)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

#Build user-space code
$(patsubst %,$(OBJ)/%.o,$(APP)): %.o: $(SKELETON)/$(APP).skel.h

$(OBJ)/$(APP).o: $(APP).c $(wildcard %.h) $(OBJ)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(APP).c -o $@

# Build application binary
$(BIN)/$(APP): $(OBJ)/$(APP).o $(OBJ) | $(BIN)
	$(Q)$(CC) $(CFLAGS) $(OBJ)/$(APP).o $(LIBBPF_OBJ) $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
