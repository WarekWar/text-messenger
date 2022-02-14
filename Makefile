CC=gcc
CFLAGS=-I. -lsctp
#CFLAGS=

OBJECTS =  chat

all: $(OBJECTS)

$(OBJECTS):%:%.c
	@echo Compiling $<  to  $@
	$(CC) -o $@ $< $(CFLAGS)

	
clean:
	rm  $(OBJECTS) 
