all : airodump

airodump: util.o apinfo.o sniffer.o airodump.o main.o 
	g++ -g -o airodump util.o apinfo.o sniffer.o airodump.o main.o -lpcap -lpthread

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

airodump.o: airodump.cpp
	g++ -g -c -o airodump.o airodump.cpp

sniffer.o: sniffer.cpp
	g++ -g -c -o sniffer.o sniffer.cpp

apinfo.o: apinfo.cpp
	g++ -g -c -o apinfo.o apinfo.cpp

util.o: util.cpp
	g++ -g -c -o util.o util.cpp

clear:
	rm -f airodump
	rm -f *.o

