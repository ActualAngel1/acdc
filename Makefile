CC := gcc
LIBRARIES := elf capstone
LIB_FLAGS := $(addprefix -l, $(LIBRARIES))
CFLAGS := -ggdb3 $(LIB_FLAGS)
OUT := ./out


all: init
	$(CC) decomp.c -o $(OUT)/decomp $(CFLAGS)

init:
	mkdir -p $(OUT)

clean:
	rm -rf $(OUT)/*

.PHONY: all clean