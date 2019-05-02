CC=gcc
CFLAGS=-c -O3 -Wall -Werror -fpic -Wno-maybe-uninitialized

SHARED_OPTS=-shared -o $(LIB_NAME) $(OBJ_NAME)

LIB=libdecode
LIB_NAME=libdecode.so
OBJ_NAME=decode.o

all: $(LIB)

$(LIB): $(OBJ_NAME)
	$(CC) $(SHARED_OPTS)

$(OBJ_NAME): $@

.c.o:
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(LIB_NAME) $(OBJ_NAME)
