

#pragma once
#include "pcapmanager.h"


mutex subMutex;
mutex sendMutex;

uint32_t Subscriber::subIDCount = 0;

Subscriber::Subscriber()
{
    //아무것도 안 함

}

Subscriber::Subscriber(int32_t layerLevel, void * box)
{
    layer = layerLevel;
    subBox = box;
    id = subIDCount;

    subIDCount ++;
}

uint32_t Subscriber::GetSubID()
{
    return id;
}


PcapManager::PcapManager(uint8_t * interface)
{
    handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 0, (char *)errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }
    printf("receiving...\n");

    thread receiver(&PcapManager::StartReceiver, this);
    receiver.detach();

}



void PcapManager::ReleaseSubcriber(Subscriber * sub)
{
    list<Subscriber *>::iterator itor;

    itor=find(subscriber.begin(), subscriber.end(), sub);  
    subscriber.erase(itor);
    
}



void PcapManager::Send(uint8_t * buf, int32_t len)
{
    unique_lock<mutex> sendMutexLock(sendMutex);
    pcap_sendpacket(handle, (const u_char *)buf, len);
    sendMutexLock.unlock();
}


void PcapManager::StartReceiver()
{
    
    struct pcap_pkthdr * header;
    const uint8_t * packet;
    Subscriber * sub;
    while(true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        for(int i =0; i< 10; i++)
        {
            printf("%x ", packet[i]);

        }
        printf("\n");



        //temp
        a.updateAP(packet);
        /*unique_lock<mutex> subMutexLock(subMutex);

        //move it to box

        //등록된 아이템일시 알람
        if( (sub = FindSubscriber(packet)) != NULL)
        {
            NoticeSubscriber(sub, packet, header->len);
        }
        */
    }
}

void PcapManager::NoticeSubscriber(Subscriber * sub, const uint8_t * packet, uint32_t len)
{

    //pass packet to the box
}



Subscriber * PcapManager::FindSubscriber(const uint8_t * packet)
{
    /*
    Subscriber packetInfo;
    struct ether_header * eth = (struct ether_header *)packet;

    switch(ntohs(eth->ether_type))
    {


    default:
        return NULL;  

    }
    
    memcpy(packetInfo.eth_src , eth->ether_shost, ETH_ALEN);
    memcpy(packetInfo.eth_dst, eth->ether_dhost, ETH_ALEN);
*/
    list<Subscriber *>::iterator itor;

    for (itor=subscriber.begin(); itor != subscriber.end(); itor++ )
    {
       /* 
        if((*itor)->proto != packetInfo.proto)
            continue;
        

        switch((*itor)->type)
        {
        case (uint32_t)SUBTYPE::GETSENDERMAC :
                
            if(memcmp((*itor)->eth_dst, packetInfo.eth_dst, ETH_ALEN))
                continue;
            
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                continue;
            
            return (*itor);    

        case (uint32_t)SUBTYPE::RELAYIP :
            
            if(memcmp((*itor)->eth_dst, packetInfo.eth_dst, ETH_ALEN))
                    continue;
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                    continue;              

            //내 IP가 목적지인 경우 넘기지 않음
            if((*itor)->ip_dst == packetInfo.ip_dst)
                    continue;
            
            return (*itor); 
            

        case (uint32_t)SUBTYPE::REACTSENDERREQUEST :
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                   continue;
            if(memcmp((*itor)->arp_sender, packetInfo.arp_sender, ETH_ALEN))
                 continue;
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                 continue;

            if((*itor)->arp_targetIP != packetInfo.arp_targetIP)
                 continue;

            return (*itor);    
            
        case (uint32_t)SUBTYPE::REACTTARGETREQUEST :
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                 continue;
            if(memcmp((*itor)->arp_sender, packetInfo.arp_sender, ETH_ALEN))
                 continue;
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                 continue;

            return (*itor);    


        }*/

        

    } //for (int i =0; i<subscriber.size(); i++)


   return NULL;
}


void PcapManager::AddSubscriber(Subscriber * sub)
{
   // unique_lock<mutex> subMutexLock(subMutex);
    subscriber.push_back(sub);
    //subMutexLock.unlock();
}



PcapManager::~PcapManager()
{
    list<Subscriber *>::iterator itor;

    for (itor=subscriber.begin(); itor != subscriber.end(); itor++)
    {

        delete(*itor);
    }
  
    subscriber.clear();

}



