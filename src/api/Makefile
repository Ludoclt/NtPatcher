CC := gcc

OBJ_DIR := ../../obj/api
BIN_DIR := ../../bin/

SRC := $(wildcard *.c)
OBJ := $(SRC:%.c=$(OBJ_DIR)/%.o)
BIN := $(BIN_DIR)/ntpatch_api.dll

DEFINES := -DDLL_EXPORTS
CFLAGS := -I../../include
LDFLAGS := -shared

ifeq (&(DEBUG),1)
	DEFINES += -DDEBUG
endif

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(DEFINES) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN)
