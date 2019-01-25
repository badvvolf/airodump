
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <list> 
#include <string.h>
#include <stdlib.h>
#include "typedef.h"
#include "apinfo.h"
#include "util.h"

using namespace std;

//to do
// - refactoring
//      change list to map
//      move codes to class
// - implement
//      specific crypto 
//      data frame 


//----- Function declaration -----

void PrintPort(u_int16_t port);
void PrintData(u_int8_t * data, u_int32_t len);
void usage() ;
Apinfo * GetAPList(u_int8_t * bssid, u_int8_t * essid, u_int32_t essidLen);
void UpdateAPList(const u_int8_t * packet);
void PrintAP();

//_____ Function declaration _____

list<Apinfo *> apList;

//----- Function definition -----
Apinfo * GetAPList(u_int8_t * bssid, u_int8_t * essid, u_int32_t essidLen)
{
    list<Apinfo *>::iterator itor;  
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
    Apinfo * ap;
    struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * bcBodyOptions = &(bcbody->options);

    if(ap = GetAPList(dot11Header->addr3, &bcBodyOptions[2] , (u_int32_t)bcBodyOptions[1]))
    {
        //update data
        Apinfo * radioInfo = Apinfo::getRadiotapInfo(radiotapHeader);
        
        //u have to check flag setting
        if(radioInfo->pwr !=0)
            ap->pwr += radioInfo->pwr;

        ap->channel = radioInfo->channel;
        ap->beacons +=1;
               
        delete(radioInfo);
    }
    else
    {
        //add new AP
        ap = Apinfo::getRadiotapInfo(radiotapHeader);
        
        memcpy(ap -> bssid, dot11Header->addr3, 6);
        ap -> beacons = 1;
        ap -> data = 0;
        ap -> essidLen =  (u_int32_t)bcBodyOptions[1];

        ap -> essid = new u_int8_t[ap ->essidLen+1];
        memcpy(ap ->essid, &bcBodyOptions[2], ap ->essidLen);
        ap -> essid[ap ->essidLen] = 0;

        if(!(bcbody->capability & IEEE80211_CAPINFO_PRIVACY))
        {
            ap->encryption =0;
        }
        else
            ap->encryption =1;

        apList.push_back(ap);
    }

   PrintAP();
}





void PrintAP()
{
    system("clear");
    //#/s : 10second data
    printf("{ BSSID | PWR | Beacons | #Data | #/s | CH | MB | ENC | CIPHER | AUTH | ESSID }\n\n");
    
    list<Apinfo *>::iterator itor; 
    for (itor=apList.begin(); itor != apList.end(); itor++ )
    {   
       (*itor)-> printAPInfo();

    } //for (itor=apList.begin(); itor != apList.end(); itor++ )

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

        radiotapHeader = (struct radiotap *)packet; 
        dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
        
        switch(dot11Header->fc)
        {
        case BEACON:
        
            UpdateAPList(packet);
            
            break;
        }

    }

} //int main(int argc, char* argv[]) 


void usage() 
{
  printf("syntax: airodump <interface>\n");
  printf("sample: airodump wlan0\n");

} //void usage() 




//_____ Function definition ______
