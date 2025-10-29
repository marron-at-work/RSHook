MAKE_PATH=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR=$(MAKE_PATH)/
BIN_DIR=$(MAKE_PATH)/../bin/
SRC_DIR=$(MAKE_PATH)/../src/

OUT_EXE=$(BUILD_DIR)output/
OUT_OBJ=$(BUILD_DIR)output/obj/

SERVER_DIR=$(SRC_DIR)server/

RSHOOK_TEST_DIR=$(MAKE_PATH)/../test/

#dev is default, for another flavor : make BUILD=release or debug
BUILD := dev

CPP=g++ 
CPP_STDFLAGS=-Wall -Wextra -Wno-unused-parameter -Wuninitialized -Werror -std=gnu++20

CPPFLAGS_OPT.debug=-O0 -g -ggdb -fno-omit-frame-pointer -fsanitize=address
CPPFLAGS_OPT.dev=-O0 -g -ggdb -fno-omit-frame-pointer
CPPFLAGS_OPT.release=-O3 -march=x86-64-v3
CPPFLAGS=${CPPFLAGS_OPT.${BUILD}} ${CPP_STDFLAGS}
CPPFLAGS_TEST=${CPPFLAGS_OPT.dev} ${CPP_STDFLAGS}

CC=gcc 
CSTDFLAGS=-DEXPORT -std=gnu17

CFLAGS_OPT.debug=-O0 -g -ggdb -fno-omit-frame-pointer
CFLAGS_OPT.dev=-O0 -g -ggdb -fno-omit-frame-pointer
CFLAGS_OPT.release=-O3 -march=x86-64-v3
CFLAGS=${CFLAGS_OPT.${BUILD}} ${CSTDFLAGS}
CFLAGS_TEST=${CFLAGS_OPT.dev} ${CSTDFLAGS}

SERVER_HEADERS=$(SERVER_DIR)server.h
SERVER_SOURCES=$(SERVER_DIR)server.c
SERVER_OBJS=$(OUT_OBJ)server.o

# MAKEFLAGS += -j4

all: $(OUT_EXE)rshook

$(OUT_EXE)rshook: $(SERVER_OBJS) $(SRC_DIR)rshook.h $(SRC_DIR)rshook.cpp
	@mkdir -p $(OUT_EXE)
	$(CPP) $(CPPFLAGS) -o $(OUT_EXE)rshook $(SERVER_OBJS) $(SRC_DIR)rshook.cpp -luring

$(OUT_OBJ)server.o: $(SERVER_HEADERS) $(SERVER_SOURCES)
	@mkdir -p $(OUT_OBJ)
	$(CC) $(CFLAGS) -o $(OUT_OBJ)server.o -c $(SERVER_SOURCES)

clean:
	rm -rf $(OUT_EXE)* $(OUT_OBJ)*.o $(BIN_DIR)*
