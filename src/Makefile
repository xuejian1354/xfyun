#common makefile header

DIR_INC = ../include
DIR_BIN = ../bin
DIR_LIB = ../libs

TARGET	= myiat
BIN_TARGET = $(DIR_BIN)/$(TARGET)

CROSS_COMPILE = 
CFLAGS = -g -Wall -I$(DIR_INC)

$(shell mkdir -p ../bin)
ifndef (LINUX64)
LINUX64 :=0
ifeq ($(shell uname -m),x86_64)
LINUX64 :=1
endif
endif

ifeq ($(LINUX64),1)
LDFLAGS := -L$(DIR_LIB)/x64
else
LDFLAGS := -L$(DIR_LIB)/x86 
endif

LDFLAGS += -lmsc -lrt -ldl -lpthread -lasound -lstdc++

OBJECTS := $(patsubst %.c,%.o,$(wildcard *.c))

$(BIN_TARGET) : $(OBJECTS)
	$(CROSS_COMPILE)gcc $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o : %.c
	$(CROSS_COMPILE)gcc -c $(CFLAGS) $< -o $@
clean:
	rm -f *.o $(BIN_TARGET)

.PHONY: clean
