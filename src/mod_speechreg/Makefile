#common makefile header

DIR_INC = ../../include
DIR_BIN = ../../bin
DIR_LIB = ../../libs

TARGET	= mod_speechreg.so
BIN_TARGET = $(DIR_BIN)/$(TARGET)

CROSS_COMPILE = 
CFLAGS = -g -fPIC -Wall -I$(DIR_INC) -I /home/sam/opensource/freeswitch/target/include/freeswitch

ifdef LINUX64
LDFLAGS := -L$(DIR_LIB)/x64 -L /home/sam/opensource/freeswitch/target/include/freeswitch/lib
else
LDFLAGS := -L$(DIR_LIB)/x86 -L /home/sam/opensource/freeswitch/target/include/freeswitch/lib
endif
LDFLAGS += -shared -lmsc -lrt -ldl -lpthread -lstdc++

OBJECTS := $(patsubst %.c,%.o,$(wildcard *.c))

$(BIN_TARGET) : $(OBJECTS)
	$(CROSS_COMPILE)gcc $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o : %.c
	$(CROSS_COMPILE)gcc -c $(CFLAGS) $< -o $@
clean:
	@rm -f *.o $(BIN_TARGET)

.PHONY:clean

#common makefile foot
