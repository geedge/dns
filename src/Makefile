CC = gcc
CCC = g++
CFLAGS = -Wall -g -fPIC
INC = -I./include/
LDFLAGS = -L./lib/
LIBS = -lMESA_handle_logger -lMESA_prof_load -lMESA_field_stat2
OBJ = dns.o
TARGET = dns.so

.c.o:
	$(CC) -c $(CFLAGS) $< $(INC)
.cpp.o:
	$(CCC) -c $(CFLAGS) $(INC) $<

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CCC) -o $@ $(OBJ) $(LDFLAGS) $(LIBS) -shared
	cp $(TARGET) ../bin/

CP:
	cp $(TARGET) ../bin/

clean:
	-rm -rf $(OBJ) $(TARGET)

.PHONY:clean
