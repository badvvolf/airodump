
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <list> 
#include <string.h>
#include <stdlib.h>

#define MACLEN 6
#define IPV4LEN 4
#define ETHHEADSIZE 14

#define RADIOTAPLEN 24
#define BEACON 0x80
using namespace std;



//----- Struct -----

class apinfo{

public:
    u_int8_t bssid[6];
    int8_t pwr;
    u_int32_t beacons;
    u_int32_t data;
    int8_t channel;
    u_int32_t essidLen;
    u_int8_t * essid;
};


struct beaconbody{

    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capability;
    u_int8_t ssid[32];

    //if you want to get more data, calculate addr with the ssid len 
}__attribute__((__packed__));;


struct dot11{

    u_int16_t fc;
    u_int16_t duid;
    u_int8_t addr1[6];
    u_int8_t addr2[6];
    u_int8_t addr3[6];
    u_int16_t sc;

}__attribute__((__packed__));;

struct radiotap{

    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;

} __attribute__((__packed__));

//_____ Struct _____

//----- Function declaration -----

void PrintPort(u_int16_t port);
void PrintData(u_int8_t * data, u_int32_t len);
void usage() ;
void PrintMACAddr(u_int8_t * addr);
apinfo * GetAPList(u_int8_t * bssid, u_int8_t * essid, u_int32_t essidLen);
void UpdateAPList(u_int8_t * packet);
void PrintAP();

//_____ Function declaration _____

list<apinfo *> apList;

//----- Function definition -----
apinfo * GetAPList(u_int8_t * bssid, u_int8_t * essid, u_int32_t essidLen)
{
    list<apinfo *>::iterator itor;
     printf("in\n");   
    for (itor=apList.begin(); itor != apList.end(); itor++ )
    {    printf("testing\n");   
        //known AP
        if(!memcmp((*itor)->bssid, bssid, 6) && (*itor)->essidLen == essidLen
            && !memcmp((*itor)->essid, essid, essidLen))
        {   
            return (*itor);
        }       
    }
    return NULL;
}

void UpdateAPList(const u_int8_t * packet)
{

    struct radiotap * radiotapHeader = (struct radiotap *)packet; ;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    apinfo * ap;
    struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));


    if(ap = GetAPList(dot11Header->addr3, &(bcbody->ssid[2]),bcbody->ssid[1]))
    {
        //update data
        
        //ap->pwr = 
        ap->beacons +=1;
    }
    else
    {
        //add new AP
        ap = new apinfo();
        
        memcpy(ap -> bssid, dot11Header->addr3, 6);
        ap -> beacons = 1;
        ap -> data = 0;
        
        ap -> essidLen = bcbody->ssid[1];
       
        ap -> essid = new u_int8_t[ap ->essidLen+1];
        memcpy(ap ->essid, &(bcbody->ssid[2]), ap ->essidLen);
        ap -> essid[ap ->essidLen] = 0;

        apList.push_back(ap);
        PrintMACAddr(ap -> bssid);
    }

    PrintAP();
}

void PrintAP()
{
    system("clear");

    printf("{ BSSID | PWR | Beacons | #Data | #/s | CH | MB | ENC | CIPHER | AUTH | ESSID }\n\n");
    
    list<apinfo *>::iterator itor; 
    for (itor=apList.begin(); itor != apList.end(); itor++ )
    {   
        PrintMACAddr((*itor)-> bssid);  
        printf(" |   |  %d  |   %d  |   |   |  |  |   |  | ", (*itor) -> beacons, (*itor) -> data );  
        
        printf("%s \n", (*itor)->essid);
    }

}


int main(int argc, char* argv[]) 
{

    if (argc != 2) 
    {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    
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

      //  printf("%d bytes header size\n", radiotapHeader->it_len);
        
        
        radiotapHeader = (struct radiotap *)packet; 
        dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
        
        switch(dot11Header->fc)
        {
        case BEACON:
        
            UpdateAPList(packet);
            
            break;





        }


    }
/*
    //----- printing MAC -----

    printf("Destination MAC : ");
    PrintMACAddr(eth->dstMAC);

    printf("Source MAC : ");
    PrintMACAddr(eth->srcMAC);  

    //_____ printing MAC ______


    //----- printing IP -----

    //check if the next protocol is IP
    if(! CheckEthType(eth->etype))
      continue;

    ip = (IPHEADER *)((u_int8_t *)eth + ETHHEADSIZE);

    printf("Destination IP : ");
    PrintIP(ip->dstIP);

    printf("Source IP : ");
    PrintIP(ip->srcIP);


    //_____ printing IP _____


    //----- printing port -----

    //check if the next protocol is TCP
    if( !CheckIPProto(ip->proto))
      continue;

    u_int32_t iplen = (u_int32_t)(ip->headerLen) * 4;
    tcp = (TCPHEADER *)((u_int8_t *)ip + iplen);


    printf("Destination Port : ");
    PrintPort(tcp->dstPort);

    printf("Source Port : ");
    PrintPort(tcp->srcPort);

    //_____ printing port _____



    //----- printing data -----
    u_int32_t dataLen = (u_int32_t)ntohs(ip->totalLen) - (u_int32_t)ip->headerLen*4 - (u_int32_t)tcp->dataOffset*4;

    if(dataLen >0)
    {
        data = (u_int8_t *)tcp + tcp->dataOffset*4;
        PrintData(data, dataLen);
    }

    //_____ printing data ______


    printf("\n");

  } //while (true) 

  pcap_close(handle);
  return 0;
*/
} //int main(int argc, char* argv[]) 


void usage() 
{
  printf("syntax: airodump <interface>\n");
  printf("sample: airodump wlan0\n");

} //void usage() 


void PrintData(u_int8_t * data, u_int32_t len)
{
  int i = 0;

  if(len >16)
    len = 16;
  
  printf("Data : ");
  for(i =0; i<len; i++)
    printf("%02x ", data[i]);

  printf("\n");

} //void PrintData(u_int8_t * data, u_int32_t len)




void PrintPort(u_int16_t port)
{
  printf("%u\n",ntohs(port) );

} //void PrintPort(u_int16_t port)



void PrintIP(u_int8_t * ipAddr)
{
  int i =0;
  for(i=0; i<IPV4LEN; i++)  
  {
    printf("%u", ipAddr[i]);

    if(i<IPV4LEN-1)
      printf("."); 
  }

  printf("\n");

} //void PrintIP(u_int8_t * ipAddr)



void PrintMACAddr(u_int8_t * addr)
{
    int i = 0;
    for(i= 0; i<MACLEN; i++)
    {
        printf("%02x", addr[i]);
        if(i < MACLEN-1)
          printf(":");
    }
} //void PrintMACAddr(u_int8_t * addr)

//_____ Function definition ______
