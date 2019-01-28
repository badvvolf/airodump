all : airodump

airodump: util.o apinfo.o pcapmanager.o airodump.o main.o 
	g++ -g -o airodump util.o apinfo.o pcapmanager.o airodump.o main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp

airodump.o:
	g++ -g -c -o airodump.o airodump.cpp

pcapmanager.o:
	g++ -g -c -o pcapmanager.o pcapmanager.cpp

apinfo.o:
	g++ -g -c -o apinfo.o apinfo.cpp

util.o:
	g++ -g -c -o util.o util.cpp

clear:
	rm -f airodump
	rm -f *.o

