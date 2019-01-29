#pragma once
#include "sniffer.h"


Subscriber::Subscriber(int32_t layerLevel,FILTER filterFunction)
{
    layer = layerLevel;
    filter = filterFunction;
 
}

u_int8_t * Subscriber::popSubBox()
{

    u_int8_t * packet = subBox.front();
    subBox.pop();
    return packet;
}

bool Subscriber::isSubBoxEmpty()
{
   
    return subBox.empty();

}

void Subscriber::pushSubBox(u_int8_t * packet)
{
    unique_lock<mutex> lck(mutexSubBox);
    subBox.push(packet);
    
    //notify if thread is waiting..
    subBoxEmpty.notify_all();
    
}


////////////////////////////////////////////////////////////////////



Sniffer::Sniffer(uint8_t * interface)
{
    handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 0, (char *)errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }
    
    thread receiver(&Sniffer::startSniffer, this);
    receiver.detach();

}

Sniffer::~Sniffer()
{
    //delete routine
}

void Sniffer::startSniffer()
{
    
    struct pcap_pkthdr * header;
    const uint8_t * packet;
    Subscriber * sub;
    while(true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // push data to subscriber
        // beware if the subscriber is multiple 
        if( (sub = findSubscriber(packet)) != NULL)
        {
            u_int8_t * packetCopy = new u_int8_t[header->len];
            memcpy(packetCopy, packet, header->len);

            //move it to box
            sendSubBox(packetCopy, sub);
        }
        
    }// while(true)

} //void Sniffer::startSniffer()


void Sniffer::sendSubBox(u_int8_t * packet, Subscriber * sub)
{
    //mutex is inside the function
    sub->pushSubBox(packet);
}

void Sniffer::addSubscriber(Subscriber * sub)
{
    unique_lock<mutex> subMutexLock(mutexSubMap);
    subscriber.insert(make_pair(sub->layer, sub));
    printf("asdasdasd\n");
    mutexSubMap.unlock();
}

Subscriber * Sniffer::findSubscriber(const uint8_t * packet)
{
 
    for(int32_t layer = (int32_t)NetworkLayer::DATALINK; layer < (int32_t)NetworkLayer::APPLICATION; layer ++)
    {
        switch(layer)
        {
        case (int32_t)NetworkLayer::PHYSICAL :
            break;

        case (int32_t)NetworkLayer::DATALINK :
        {
            pair<submapItor, submapItor> equalLevSub = subscriber.equal_range((int32_t)NetworkLayer::DATALINK);

            for (submapItor iter = equalLevSub.first; iter != equalLevSub.second; iter++)
            {  
               
                //use check function which registered 
               if((iter->second->filter)(packet))
               {
                     
                   return iter->second;
               }
            }

            break;
        } //case (int32_t)NetworkLayer::DATALINK

        case (int32_t)NetworkLayer::NETWORK:
            break;
        case (int32_t)NetworkLayer::TRANSPORT:
            break;
        case (int32_t)NetworkLayer::SESSION:
            break;
        case (int32_t)NetworkLayer::PRESENTATION:
            break;
        case (int32_t)NetworkLayer::APPLICATION:
            break;

        } //switch(layer)


    } //for(int32_t layer = (int32_t)NetworkLayer::DATALINK; layer < (int32_t)NetworkLayer::APPLICATION; layer ++)

   return NULL;

} //Subscriber * Sniffer::findSubscriber(uint8_t * packet)


