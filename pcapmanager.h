
#pragma once

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <list>
#include <algorithm>
#include <string.h>
#include <netinet/ether.h>
#include <thread>  
//#include <netinet/ip.h>
#include <mutex>
#include <condition_variable>
#include "typedef.h"
#include "airodump.h"

using namespace std;


enum class NetworkLayer
{
    PHYSICAL = 1,
    DATALINK,
    NETWORK,
    TRANSPORT,
    SESSION,
    PRESENTATION,
    APPLICATION

};


class Subscriber
{
private:
   
public:
    static uint32_t subIDCount;
    
    u_int32_t id;
    int32_t layer;

    void * subBox;
    
    

   Subscriber(int32_t layerLevel, void * box);
    

    Subscriber();
    uint32_t GetSubID();
};


class PcapManager
{

private:
    
    pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    list <Subscriber *> subscriber;
    Airodump a;
public:
    PcapManager(uint8_t * );
    ~PcapManager();

    void Send(uint8_t * buf, int32_t len);
    void StartReceiver();


    void AddSubscriber(Subscriber * sub);
    void ReleaseSubcriber(Subscriber * sub);
    void NoticeSubscriber(Subscriber * sub, const uint8_t * , uint32_t);
    Subscriber * FindSubscriber(const uint8_t * packet);

};



