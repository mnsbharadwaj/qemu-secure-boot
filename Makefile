# -------- Toolchain --------
TOOLPREFIX ?= riscv64-unknown-elf-
CC      := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
OBJDUMP := $(TOOLPREFIX)objdump
READELF := $(TOOLPREFIX)readelf

# -------- Project Layout --------
# Root has startup.s, vectors.S, linker.ld, and C files (e.g., main.c, aes_*).
SFR_DIR  := sfr
TEST_DIR := test
SRC_DIRS := . $(SFR_DIR) $(TEST_DIR)
BUILD    := build

# -------- Configurable ISA/ABI --------
# Use: make run ARCH=rv64 FLOAT=soft     or    ARCH=rv32 FLOAT=hard
ARCH  ?= rv64            # rv64 | rv32
FLOAT ?= soft            # soft | hard

ifeq ($(ARCH),rv32)
  ifeq ($(FLOAT),hard)
    MARCH := rv32imafdc
    MABI  := ilp32d
  else
    MARCH := rv32imac
    MABI  := ilp32
  endif
  QEMU  := qemu-system-riscv32
  ELFEMU:= elf32lriscv
else
  ifeq ($(FLOAT),hard)
    MARCH := rv64gc
    MABI  := lp64d
  else
    MARCH := rv64imac
    MABI  := lp64
  endif
  QEMU  := qemu-system-riscv64
  ELFEMU:= elf64lriscv
endif

# -------- Includes / Flags --------
INCLUDES := $(addprefix -I,$(SRC_DIRS))
COMMON_CFLAGS := -march=$(MARCH) -mabi=$(MABI) -mcmodel=medany -Os -g \
                 -ffreestanding -nostdlib -fno-builtin -fno-exceptions \
                 -Wall -Wextra -Wundef -Werror=implicit-function-declaration \
                 -MMD -MP $(INCLUDES)
CFLAGS   := $(COMMON_CFLAGS)
ASFLAGS  := $(COMMON_CFLAGS)            # assemble .s with same ISA/ABI
LDFLAGS  := -T linker.ld -Wl,-m,$(ELFEMU) -nostartfiles -nostdlib -Wl,--gc-sections

# -------- Sources / Objects --------
# C sources from root + sfr + test
C_SRCS := $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c))
# Assembly (.s / .S) from root only (edit if you place them elsewhere)
S_SRCS := $(wildcard *.s) $(wildcard *.S)

# Map sources to build/ objects mirroring paths
C_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(C_SRCS))
S_OBJS := $(patsubst %.s,$(BUILD)/%.o,$(S_SRCS))
S_OBJS := $(patsubst %.S,$(BUILD)/%.o,$(S_OBJS))
OBJS   := $(C_OBJS) $(S_OBJS)

# Dependency files
DEPS := $(OBJS:.o=.d)

# -------- Targets --------
.PHONY: all clean run size tree

all: $(BUILD)/firmware.elf $(BUILD)/firmware.bin $(BUILD)/firmware.dump

# Ensure build/ subdirs exist (build/, build/sfr, build/test)
$(BUILD):
	@mkdir -p $(addprefix $(BUILD)/,$(SRC_DIRS))

# Pattern rule: C -> .o (into build/)
$(BUILD)/%.o: %.c | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Pattern rule: asm -> .o (into build/)
$(BUILD)/%.o: %.s | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

# Link
$(BUILD)/firmware.elf: $(OBJS) linker.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

# Binary / dump
$(BUILD)/firmware.bin: $(BUILD)/firmware.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD)/firmware.dump: $(BUILD)/firmware.elf
	$(OBJDUMP) -D $< > $@

# Run on QEMU virt (UART at 0x10000000; -nographic puts logs in the console)
run: $(BUILD)/firmware.elf
	$(QEMU) -machine virt -nographic -kernel $<

# Optional helpers
size: $(BUILD)/firmware.elf
	$(READELF) -h $< | sed -n 's/.*Class.*/&/p'
	$(OBJDUMP) -h $< | grep -E '\.vectors|\.text|\.data|\.bss|\.stackconst'

tree:
	@echo "C_SRCS:  $(C_SRCS)"
	@echo "S_SRCS:  $(S_SRCS)"
	@echo "OBJS:    $(OBJS)"

clean:
	rm -rf $(BUILD)

# Include auto-generated dependencies
-include $(DEPS)
