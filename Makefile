CC=gcc
CFLAGS=-I. -lm
#CFLAGS=

OBJECTS = telnet_cli telnet_serv

all: $(OBJECTS)

$(OBJECTS):%:%.c
	@echo Compiling $<  to  $@
	$(CC) -o $@ $< $(CFLAGS)

	
clean:
	rm  $(OBJECTS) 
