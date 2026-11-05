CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic -O2 -D_GNU_SOURCE
SRC = src/main.c
TARGET = ushieldd

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
