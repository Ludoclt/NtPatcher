CC := gcc

ASM_DIR := ../asm
OBJ_DIR := ../obj
BIN_DIR := ../bin

ASM := $(wildcard $(ASM_DIR)/*.s)
SRC := $(wildcard *.c)
OBJ := $(ASM:$(ASM_DIR)/%.s=$(OBJ_DIR)/%.o) $(SRC:%.c=$(OBJ_DIR)/%.o)
BIN := $(BIN_DIR)/ntpatch.dll

DEF_FILE := ntpatch.def

DEFINES :=
CFLAGS := -I../include
LDFLAGS := -shared

ifeq ($(DEBUG),1)
	DEFINES += -DDEBUG
endif

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@ $(DEF_FILE)

$(OBJ_DIR)/%.o: $(ASM_DIR)/%.s | $(OBJ_DIR)
	$(CC) -c $< -o $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(DEFINES) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN)
