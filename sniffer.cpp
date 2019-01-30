#pragma once
#include "sniffer.h"


Subscriber::Subscriber(int32_t layerLevel,FILTER filterFunction)
{
    layer = layerLevel;
    filter = filterFunction;
 
}

SubBoxContent * Subscriber::popSubBox()
{
    SubBoxContent * content = subBox.front();
    subBox.pop();
    return content;
}

bool Subscriber::isSubBoxEmpty()
{
   
    return subBox.empty();

}

void Subscriber::pushSubBox(SubBoxContent * content)
{
    unique_lock<mutex> lck(mutexSubBox);
    subBox.push(content);
    
    //notify if thread is waiting..
    subBoxEmpty.notify_all();
    
}


////////////////////////////////////////////////////////////////////



SubBoxContent::SubBoxContent(struct pcap_pkthdr * header, u_int8_t * p)
{
    pcapheader = header;
    packet = p;

}

SubBoxContent::~SubBoxContent()
{
    delete(packet);
    free(pcapheader);
}



////////////////////////////////////////////////////////////////////////



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

            struct pcap_pkthdr * pcapheader = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
            memcpy(pcapheader, header, sizeof(struct pcap_pkthdr));

            SubBoxContent * content = new SubBoxContent(pcapheader, packetCopy);

            //move it to box
            sendSubBox(content, sub);
        }
        
    }// while(true)

} //void Sniffer::startSniffer()


void Sniffer::sendSubBox(SubBoxContent * content, Subscriber * sub)
{
    //mutex is inside the function
    sub->pushSubBox(content);
}

void Sniffer::addSubscriber(Subscriber * sub)
{
    unique_lock<mutex> subMutexLock(mutexSubMap);
    subscriber.insert(make_pair(sub->layer, sub));
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


