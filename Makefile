all : airodump

airodump: util.o apinfo.o main.o 
	g++ -g -o airodump util.o apinfo.o main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

apinfo.o:
	g++ -g -c -o apinfo.o apinfo.cpp

util.o:
	g++ -g -c -o util.o util.cpp

clear:
	rm -f airodump
	rm -f *.o

