#include "airodump.h"

Airodump::Airodump(uint8_t * dev)
{
    subBeacon = new Subscriber(2, (FILTER)&Airodump::filterBeacon);
    sniffer = new Sniffer(dev);
    sniffer->addSubscriber(subBeacon);

}


void Airodump::start()
{
    thread beaconSubBoxChecker(&Airodump::checkBeaconSubBox, this);

    //add probeSubBoxChecker



    beaconSubBoxChecker.join();
}

bool Airodump::filterBeacon(const u_int8_t * packet)
{
    struct radiotap * radiotapHeader;
    struct dot11 * dot11Header;
   
    radiotapHeader = (struct radiotap *)packet; 
    dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    if(dot11Header->fc == BEACON)
            return true;

    return false; 
}

//how about make "subbox" class and get the value bu function?
void Airodump::checkBeaconSubBox()
{
    while(1)
    {
        unique_lock<mutex> lck(subBeacon->mutexSubBox);
        while (subBeacon->isSubBoxEmpty())
            subBeacon->subBoxEmpty.wait(lck);

        const u_int8_t * packet = subBeacon->popSubBox();
        lck.unlock();

        updateAP(packet);
    }
}
/*
void Airodump::checkProbeSubBox()
{

    std::unique_lock<std::mutex> lck(subProbe->mutexSubBox);

    while (!subProbe->isSubBoxEmpty())
        subProbe->subBoxEmpty.wait(lck);

    updateAP(subProbe->popSubBox());

}
*/



void Airodump::updateAP(const u_int8_t * packet)
{
    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    Apinfo * ap;
    struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * bcBodyOptions = &(bcbody->options);

    if(ap = getAP((macaddr)dot11Header->addr3, &bcBodyOptions[2] , (u_int32_t)bcBodyOptions[1]))
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
        ap->bssid = dot11Header->addr3;

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
        
        
        apInfoMap.insert(make_pair(ap->bssid, ap));

    }

    printAll();

}


Apinfo *  Airodump::getAP(macaddr bssid, u_int8_t * essid, u_int32_t essidLen)
{

    pair<apmapItor, apmapItor> result = apInfoMap.equal_range(bssid);
    
    for (apmapItor iter = result.first; iter != result.second; iter++)
    {
        if(!memcmp(iter->second->essid, essid, essidLen))
        { 
            return iter->second;
        }
    }

    return NULL;

}

void Airodump::printAll()
{
    system("clear");
    printAP();

    //printProbe()


}

void Airodump::printAP()
{

    printf("{ BSSID | PWR | Beacons | #Data | #/s | CH | MB | ENC | CIPHER | AUTH | ESSID }\n\n");

    for (apmapItor iter = apInfoMap.begin(); iter != apInfoMap.end(); iter ++)
    {
        iter->second->printAPInfo();

    }

}