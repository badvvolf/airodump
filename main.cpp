
#include <stdio.h>

#include "pcapmanager.h"
#include "airodump.h"

//to do
// modify function name...
// refactoring
// - implement
//      specific crypto 
//      data frame 
//      pcap manager : subscribe, box
//      airodump : access the box 


void usage();

int main(int argc, char* argv[]) 
{

    if (argc != 2) 
    {
        usage();
        return -1;
    }

    uint8_t * dev = (uint8_t * )argv[1];
    
    PcapManager * pcapMngr = new PcapManager(dev);

    //subscribe 
    while(1);



/*
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //get packet and write infomation
    while (true) 
    {
        struct pcap_pkthdr * header;
        const u_int8_t * packet;

        //pointers to read datas
        struct radiotap * radiotapHeader;
        struct dot11 * dot11Header;
        u_int8_t * data;
        
        int i = 0;

        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break; 

        radiotapHeader = (struct radiotap *)packet; 
        dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
        
        switch(dot11Header->fc)
        {
        case BEACON:
        
            UpdateAPList(packet);
            
            break;
        }
       

    }*/

} //int main(int argc, char* argv[]) 


void usage() 
{
  printf("syntax: airodump <interface>\n");
  printf("sample: airodump wlan0\n");

} //void usage() 




//_____ Function definition ______
