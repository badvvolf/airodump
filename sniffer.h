
#pragma once

#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include <thread>  
#include <mutex>
#include <condition_variable>

#include <queue>
#include <map>

#include "typedef.h"


using namespace std;


class SubBoxContent{

public:
    struct pcap_pkthdr * pcapheader;
    u_int8_t * packet;

    SubBoxContent(struct pcap_pkthdr * , u_int8_t *);
    ~SubBoxContent();
};


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

//filter function pointer
typedef bool (*FILTER)(const u_int8_t *);

class Subscriber
{
private:
    queue<SubBoxContent *> subBox;
public:
    
    // network layer of filter
    int32_t layer;

    // filter function pointer
    FILTER filter;
  
    condition_variable subBoxEmpty;
    mutex mutexSubBox;
 
    Subscriber(int32_t, FILTER);
    
    void pushSubBox(SubBoxContent *);
    SubBoxContent * popSubBox();
    bool isSubBoxEmpty();

};

typedef multimap<int32_t, Subscriber *>::iterator submapItor;

class Sniffer
{

private:

    //pcap
    pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];


    multimap <int32_t, Subscriber *> subscriber;
    mutex mutexSubMap;

public:
    Sniffer(uint8_t * );
    ~Sniffer();

    void startSniffer();

    void addSubscriber(Subscriber * );
    void sendSubBox(SubBoxContent * , Subscriber * );

    Subscriber * findSubscriber(const uint8_t * );

};



