
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


enum ieee80211_radiotap_presence {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	/* 18 is XChannel, but it's not defined yet */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};


struct radiotap_channel{

    u_int16_t frequency;
    u_int16_t flags;

}__attribute__((__packed__));

class apinfo{

public:
    u_int8_t bssid[6];
    int8_t pwr;
    u_int32_t beacons;
    u_int32_t data;
    u_int16_t channel;
    u_int32_t essidLen;
    u_int8_t * essid;
}; 


struct beaconbody{

    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capability;
    u_int8_t ssid[32];

    //if you want to get more data, calculate addr with the ssid len 
}__attribute__((__packed__));


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
void UpdateAPList(const u_int8_t * packet);
void PrintAP();
apinfo * GetRadiotapInfo(struct radiotap * radiotapHeader);

//_____ Function declaration _____

list<apinfo *> apList;

//----- Function definition -----
apinfo * GetAPList(u_int8_t * bssid, u_int8_t * essid, u_int32_t essidLen)
{
    list<apinfo *>::iterator itor;  
    for (itor=apList.begin(); itor != apList.end(); itor++ )
    {  
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

    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    apinfo * ap;
    struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));


    if(ap = GetAPList(dot11Header->addr3, &(bcbody->ssid[2]),bcbody->ssid[1]))
    {
        //update data
        apinfo * radioInfo = GetRadiotapInfo(radiotapHeader);
        
        ap->pwr = radioInfo->pwr;
        ap->channel = radioInfo->channel;
        ap->beacons +=1;

        delete(radioInfo);
    }
    else
    {
        //add new AP
        ap = GetRadiotapInfo(radiotapHeader);
        
        memcpy(ap -> bssid, dot11Header->addr3, 6);
        ap -> beacons = 1;
        ap -> data = 0;
        ap -> essidLen = bcbody->ssid[1];

        ap -> essid = new u_int8_t[ap ->essidLen+1];
        memcpy(ap ->essid, &(bcbody->ssid[2]), ap ->essidLen);
        ap -> essid[ap ->essidLen] = 0;

        apList.push_back(ap);
    }

   PrintAP();
}

apinfo * GetRadiotapInfo(struct radiotap * radiotapHeader)
{

    //to check all radiotap header
    apinfo * ap = new apinfo();
    u_int32_t count = 1;
    for(u_int32_t * rdcount = (u_int32_t *)&(radiotapHeader->it_present); (*rdcount) & (1 << IEEE80211_RADIOTAP_EXT); rdcount ++)
    {
        count ++;
    }

    //get start point
    u_int8_t * ptr = (u_int8_t *)&(radiotapHeader->it_present) + 4*count;
    u_int32_t * it_present = (u_int32_t *)&radiotapHeader->it_present;
    for(u_int32_t i =0; i<count; i++)
    {
        //just add pointer which is not interested
        if(*it_present& (1<<IEEE80211_RADIOTAP_TSFT)) //0
        {
            //if you want to use this flag's infomation
            //remove the add code and write code here
            ptr += 8;
        }

        if(*it_present & (1<<IEEE80211_RADIOTAP_FLAGS)) //1
        {
            ptr += 1;
        }

        if(*it_present & (1<<IEEE80211_RADIOTAP_RATE)) //2
        {
            ptr += 1;
        }
        if(*it_present & (1 << IEEE80211_RADIOTAP_CHANNEL)) //3
        {
            struct radiotap_channel * channel = (struct radiotap_channel *)ptr;
            ap->channel = (channel->frequency - 2412)/5 +1;
            ptr += sizeof(struct radiotap_channel);
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_FHSS)) //4
        {
                ptr += 2;
        }
        //average??????????
        if (*it_present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) //5
        {
            
            ap->pwr = (int8_t)(*ptr);
            //maybe alignment
            ptr += 2;
            
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE)) //6
        {
                ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_LOCK_QUALITY)) //7
        {
            ptr +=2;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_TX_ATTENUATION)) //8
        {
            ptr +=2;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DB_TX_ATTENUATION)) //9
        {
            ptr +=2;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DBM_TX_POWER)) //10
        {
            ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_ANTENNA)) //11
        {
            ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)) //12
        {
            ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DB_ANTNOISE)) //13
        {
            ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_RX_FLAGS)) //14
        {
            ptr +=2;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_TX_FLAGS)) //15
        {
            ptr +=2;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_RTS_RETRIES)) //16
        {
            ptr += 1;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_DATA_RETRIES)) //17
        {
            ptr += 1;
        }

        /////////////////////no 18

        if (*it_present & (1 << IEEE80211_RADIOTAP_MCS)) //19
        {
            ptr +=3;
        }


        if (*it_present & (1 << IEEE80211_RADIOTAP_AMPDU_STATUS)) //20
        {
            ptr +=8;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_VHT)) //21
        {
            ptr +=12;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_TIMESTAMP)) //22
        {
            ptr +=12;

        }
        
        ///////////////////////////23
        ///////////////////////////24
        ///////////////////////////25
        ///////////////////////////26
        ///////////////////////////27
        ///////////////////////////28

        //???????????????
        if (*it_present & (1 << IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) //29
        {

        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_VENDOR_NAMESPACE)) //30
        {
            ptr +=6;
        }
        if (*it_present & (1 << IEEE80211_RADIOTAP_EXT)) //31
        {
            
        }

        //see next flag
        it_present ++;


    }

    return ap;

}


void PrintAP()
{
    system("clear");

    printf("{ BSSID | PWR | Beacons | #Data | #/s | CH | MB | ENC | CIPHER | AUTH | ESSID }\n\n");
    
    list<apinfo *>::iterator itor; 
    for (itor=apList.begin(); itor != apList.end(); itor++ )
    {   
        PrintMACAddr((*itor)-> bssid);  
        printf(" | %d  |  %d  |   %d  |   |   | %d |  |   |  | ", (*itor) ->pwr, (*itor) -> beacons, (*itor) -> data , (*itor)->channel);  
        
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
