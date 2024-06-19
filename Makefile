LDLIBS=-lpcap

all: tcp-block

tcp-block: ethhdr.o ip.o mac.o main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
