CC = gcc
CFLAGS = -Wall -Wextra -g
BIN := ../../.bin
TARGET = $(BIN)/ptrace_example
KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)/include/

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -I$(KERNEL_HEADERS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean