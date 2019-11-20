CC = g++
CFLAGS = -W -Wall
TARGET = tcp_block 
OBJECTS = main.o utils.o packet.o

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ -lpcap

clean :
	rm -f *.o $(TARGET)
