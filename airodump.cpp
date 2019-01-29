#include "airodump.h"

Airodump::Airodump(uint8_t * dev)
{
    subBeacon = new Subscriber(2, (FILTER)&Airodump::filterBeacon);
    subData = new Subscriber(2, (FILTER)&Airodump::filterData);

    sniffer = new Sniffer(dev);
    sniffer->addSubscriber(subBeacon);
    sniffer->addSubscriber(subData);
}


void Airodump::start()
{
    thread beaconSubBoxManger(&Airodump::manageSubBox, this, subBeacon);
    thread dataSubBoxManager(&Airodump::manageSubBox, this, subData);
    //add probeSubBoxChecker



    beaconSubBoxManger.join();
    dataSubBoxManager.join();
}


bool Airodump::filterBeacon(const u_int8_t * packet)
{
    struct radiotap * radiotapHeader;
    struct dot11 * dot11Header;
   
    radiotapHeader = (struct radiotap *)packet; 
    dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);

    u_int8_t fcType = (dot11Header->fc & IEEE80211_FC0_TYPE_MASK) ;
    u_int8_t fcSubtype = (dot11Header->fc & IEEE80211_FC0_SUBTYPE_MASK);

    if(fcType == IEEE80211_FC0_TYPE_MGT && fcSubtype== IEEE80211_FC0_SUBTYPE_BEACON)
    {
        return true;
    }
    return false; 
}

bool Airodump::filterData(const u_int8_t * packet)
{
    struct radiotap * radiotapHeader;
    struct dot11 * dot11Header;
   
    radiotapHeader = (struct radiotap *)packet; 
    dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);

    u_int8_t fcType = (dot11Header->fc & IEEE80211_FC0_TYPE_MASK);
    u_int8_t fcSubtype = (dot11Header->fc & IEEE80211_FC0_SUBTYPE_MASK);
    if(fcType == IEEE80211_FC0_TYPE_DATA && fcSubtype== IEEE80211_FC0_SUBTYPE_DATA)
    {
        return true;
    }
    return false; 
}



//how about make "subbox" class and get the value by function?
void Airodump::manageSubBox(Subscriber * sub)
{
    while(1)
    {
       
        unique_lock<mutex> lck(sub->mutexSubBox);
        while (sub->isSubBoxEmpty())
            sub->subBoxEmpty.wait(lck);

        u_int8_t * packet = sub->popSubBox();
        lck.unlock();
        
        if(sub == subBeacon)
            updateAP(packet);
        else if(sub == subData)
            updateData(packet);


    }
}

void Airodump::updateData(u_int8_t * packet)
{
    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    Apinfo * ap;

   /* struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * bcBodyOptions = &(bcbody->options);*/


    if(ap = getAP((macaddr)dot11Header->addr3, NULL , 0))
    {
        //update data
        Apinfo * radioInfo = Apinfo::getRadiotapInfo(radiotapHeader);
        
        //u have to check flag setting
        if(radioInfo->pwr !=0)
            ap->pwr += radioInfo->pwr;

        ap->channel = radioInfo->channel;
        ap->data +=1;
        
        ap->total +=1;
        delete(radioInfo);
    }
    else
    {
        //add new AP
        ap = Apinfo::getRadiotapInfo(radiotapHeader);
        ap->bssid = dot11Header->addr3;

        ap -> beacons = 0;
        ap -> data = 1;
        ap -> essidLen =  0;

        /*
        if(!(bcbody->capability & IEEE80211_CAPINFO_PRIVACY))
        {
            ap->encryption =0;
        }
        else
            ap->encryption =1;
        */

        ap->total =1;

        apInfoMap.insert(make_pair(ap->bssid, ap));

    }

    delete(packet);

    printAll();


}

void Airodump::updateAP(u_int8_t * packet)
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

        if(ap->essidLen ==0)
        {
            ap -> essid = new u_int8_t[ap ->essidLen+1];
            memcpy(ap ->essid, &bcBodyOptions[2], ap ->essidLen);
            ap -> essid[ap ->essidLen] = 0;
        }
        
        ap->total +=1;

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
        
        ap->total =1;


        apInfoMap.insert(make_pair(ap->bssid, ap));

    }

    delete(packet);

    printAll();

}


Apinfo *  Airodump::getAP(macaddr bssid, u_int8_t * essid, u_int32_t essidLen)
{
    //return apInfoMap.find(bssid)->second;

    apmapItor iter = apInfoMap.find(bssid);
    if(iter == apInfoMap.end())
        return NULL;
    else
    {
        //return the last one
        return iter->second;
    }
    
/*
    pair<apmapItor, apmapItor> result = apInfoMap.equal_range(bssid);
    
    for (apmapItor iter = result.first; iter != result.second; iter++)
    {
        //if there was only data packet
        if(iter->second->essidLen == 0)
            continue;

        if(!memcmp(iter->second->essid, essid, essidLen))
        { 
            return iter->second;
        }
    }

    return NULL;
*/
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