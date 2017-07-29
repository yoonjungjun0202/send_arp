CC = gcc
TARGET = send_arp
OBJECTS = main.c
LIBS = -lpcap

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm $(TARGET)
