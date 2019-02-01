#include "airodump.h"

Airodump::Airodump(uint8_t * dev)
{
    subBeacon = new Subscriber(2, (FILTER)&Airodump::filterBeacon);
    subData = new Subscriber(2, (FILTER)&Airodump::filterData);
    subProbeReq = new Subscriber(2, (FILTER)&Airodump::filterProbeReq);

    sniffer = new Sniffer(dev);
    
    sniffer->addSubscriber(subBeacon);
    sniffer->addSubscriber(subData);
    sniffer->addSubscriber(subProbeReq);
}


void Airodump::start()
{
    thread beaconSubBoxManger(&Airodump::manageSubBox, this, subBeacon);
    thread dataSubBoxManager(&Airodump::manageSubBox, this, subData);
    thread probeSubBoxManager(&Airodump::manageSubBox, this, subProbeReq);


    beaconSubBoxManger.join();
    dataSubBoxManager.join();
}


bool Airodump::filterProbeReq(const u_int8_t * packet)
{
    struct radiotap * radiotapHeader;
    struct dot11 * dot11Header;
   
    radiotapHeader = (struct radiotap *)packet; 
    dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);

    u_int8_t fcType = (dot11Header->fc & IEEE80211_FC0_TYPE_MASK) ;
    u_int8_t fcSubtype = (dot11Header->fc & IEEE80211_FC0_SUBTYPE_MASK);

    if(fcType == IEEE80211_FC0_TYPE_MGT && fcSubtype== IEEE80211_FC0_SUBTYPE_PROBE_REQ)
    {
        return true;
    }
    return false; 


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

        SubBoxContent * content = sub->popSubBox();

        lck.unlock();
        
        if(sub == subBeacon)
            updateAP(content);
        else if(sub == subData)
            updateData(content);
        else if (sub == subProbeReq)
            updateProbeReq(content);


    }
}



void Airodump::updateProbeReq(SubBoxContent * content)
{
    u_int8_t * packet = content->packet;

    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    ProbeInfo * pi;
   // struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * probeReqTags = (u_int8_t *)dot11Header + sizeof(dot11);
    RadioTapInfo * rt = new RadioTapInfo();
 
    if(pi = getPI((macaddr)dot11Header->addr2, (macaddr)dot11Header->addr3, &probeReqTags[2] , (u_int32_t)probeReqTags[1]))
    {
        //update data
        
        getRadiotapInfo(radiotapHeader, rt);

        pi->pwr += rt->pwr;
        pi->pwrcount +=1;

        pi->frame +=1;

        //if data frame arrived first
        if(pi->essidLen ==0 && (u_int32_t)probeReqTags[1] >0 )
        {
            pi -> essidLen =  (u_int32_t)probeReqTags[1];
            pi -> essid = new u_int8_t[pi ->essidLen+1];
            memcpy(pi ->essid, &probeReqTags[2], pi ->essidLen);
            pi -> essid[pi ->essidLen] = 0;
        }

    }
    else
    {
        //add new AP
        pi = new ProbeInfo();
        
        getRadiotapInfo(radiotapHeader, rt);


        pi->pwr = rt->pwr;
        pi->pwrcount +=1;
        pi->bssid = dot11Header->addr3;
       
        pi->station =  dot11Header->addr2;
       

        pi -> frame = 1;

        if((u_int32_t)probeReqTags[1] > 0)
        {
            pi -> essidLen =  (u_int32_t)probeReqTags[1];

            pi -> essid = new u_int8_t[pi ->essidLen+1];
            memcpy(pi ->essid, &probeReqTags[2], pi ->essidLen);
            pi -> essid[pi ->essidLen] = 0;
        }

        
        piInfoMap.insert(make_pair(pi->station, pi));

    }


    delete(content);
    delete(rt);


    printAll();

}

void Airodump::updateData(SubBoxContent * content)
{
    u_int8_t * packet = content->packet;

    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    Apinfo * ap;
    RadioTapInfo * rt = new RadioTapInfo();
   /* struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * bcbodyTags = &(bcbody->options);*/


    if(ap = getAP((macaddr)dot11Header->addr3, NULL , 0))
    {
        //update data
        getRadiotapInfo(radiotapHeader, rt);
        ap->pwr += rt->pwr;
        ap->pwrcount +=1;
        ap->channel = rt->channel;

        ap->data +=1;
  
    }
    else
    {
        //add new AP
 
        ap = new Apinfo();

        getRadiotapInfo(radiotapHeader, rt);

        ap->pwr = rt->pwr;
        ap->pwrcount +=1;

        ap->channel = rt->channel;

        ap->bssid = dot11Header->addr3;
        
        
        ap -> data = 1;

        /*
        if(!(bcbody->capability & IEEE80211_CAPINFO_PRIVACY))
        {
            ap->encryption =0;
        }
        else
            ap->encryption =1;
        */

        

        apInfoMap.insert(make_pair(ap->bssid, ap));

    }

    delete(content);
    delete(rt);

    printAll();


}

void Airodump::updateAP(SubBoxContent * content)
{
    u_int8_t * packet = content->packet;


    struct radiotap * radiotapHeader = (struct radiotap *)packet;
    struct dot11 * dot11Header = (struct dot11 *)((u_int8_t *)packet + radiotapHeader->it_len);
    Apinfo * ap;
    struct beaconbody * bcbody = (struct beaconbody *)((u_int8_t *)dot11Header + sizeof(dot11));

    u_int8_t * bcbodyTags = &(bcbody->tags);

    RadioTapInfo * rt = new RadioTapInfo();

    if(ap = getAP((macaddr)dot11Header->addr3, &bcbodyTags[2] , (u_int32_t)bcbodyTags[1]))
    {
        //update data

        getRadiotapInfo(radiotapHeader, rt);

        ap->beacons +=1;

        ap->pwr += rt->pwr;
        ap->pwrcount +=1;

        ap->channel = rt->channel;

        //if data frame arrived first
        if(ap->essidLen ==0 && (u_int32_t)bcbodyTags[1] >0 )
        {
            ap -> essidLen =  (u_int32_t)bcbodyTags[1];
            ap -> essid = new u_int8_t[ap ->essidLen+1];
            memcpy(ap ->essid, &bcbodyTags[2], ap ->essidLen);
            ap -> essid[ap ->essidLen] = 0;
        }

    }
    else
    {
        //add new AP
        ap = new Apinfo();
        
        getRadiotapInfo(radiotapHeader, rt);

        ap->pwr = rt->pwr;
        ap->pwrcount +=1;
        ap->channel = rt->channel;

        ap->bssid = dot11Header->addr3;

        ap -> beacons = 1;

        if((u_int32_t)bcbodyTags[1] > 0)
        {
            ap -> essidLen =  (u_int32_t)bcbodyTags[1];

            ap -> essid = new u_int8_t[ap ->essidLen+1];
            memcpy(ap ->essid, &bcbodyTags[2], ap ->essidLen);
            ap -> essid[ap ->essidLen] = 0;
        }

        getCrypto(packet, bcbody, content->pcapheader->len, ap);
        

        apInfoMap.insert(make_pair(ap->bssid, ap));

    }

    delete(content);
    delete(rt);

    printAll();

}

ProbeInfo * Airodump::getPI(macaddr station, macaddr bssid, u_int8_t * essid, u_int32_t essidLen)
{
    //return apInfoMap.find(bssid)->second;
    pimapItor iter = piInfoMap.find(station);

    if(iter == piInfoMap.end())
        return NULL;
  
    pair<pimapItor, pimapItor> result = piInfoMap.equal_range(station);
    
    for (pimapItor iter = result.first; iter != result.second; iter++)
    {
        if(essidLen == 0)
        {
            //bssid
            if(iter->second->essidLen == 0 && iter->second->bssid == bssid)
            {
                return iter->second;
            }
        }
        if(essidLen != 0)
        {
            if(iter->second->essidLen != 0 
                && !memcmp(iter->second->essid, essid, essidLen
                && iter->second->bssid == bssid))
            { 
                return iter->second;
            }
        }
    }

    return NULL;


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
   printProbe();


}

void Airodump::printProbe()
{
    printf("{ BSSID | STATION | PWR | RATE | Lost  | Frames | Probe }\n\n");

    for (pimapItor iter = piInfoMap.begin(); iter != piInfoMap.end(); iter ++)
    {
        iter->second->printPIInfo();

    }

    
}

void Airodump::printAP()
{

    printf("{ BSSID | PWR | Beacons | #Data | #/s | CH | MB | ENC | CIPHER | AUTH | ESSID }\n\n");

    for (apmapItor iter = apInfoMap.begin(); iter != apInfoMap.end(); iter ++)
    {
        iter->second->printAPInfo();

    }

    printf("\n");

}


void Airodump::getCrypto(u_int8_t * packet, struct beaconbody * bcbody , u_int32_t packetLen, Apinfo * ap)
{
    
    u_int8_t * bcbodyTags = &(bcbody->tags);
  

    if(bcbody->capability & IEEE80211_CAPINFO_PRIVACY)
    {
        ap->encryption |= STD_WEP | ENC_WEP; 
    }
    else
        ap->encryption =STD_OPN;
    
   
    //check the tags
    while (bcbodyTags < packet + packetLen)
    {
        u_int8_t type = bcbodyTags[0];
        u_int8_t length = bcbodyTags[1];

 
        //pass the weird packet
        if (bcbodyTags + 2 + length >  packet + packetLen)
        {
            break;
        }

        // Vender spesific / RSN tags
        if ( (type == BEACONTAG_VENDERSPESIFIC && length >= 8
                && (memcmp(bcbodyTags + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
            || (type == BEACONTAG_RSNIE))
        {
            ap->encryption &= ~(STD_WEP | ENC_WEP | STD_WPA);
            
            int32_t numUniCiperSuite = 0;
            int32_t numAKM =0;
            u_int8_t offset = 0;

            switch (type)
            {
            case BEACONTAG_RSNIE:
                //if there is rsn ie tag, it's wpa2
                ap->encryption |= STD_WPA2;
                offset = 0;
                break;

            case BEACONTAG_VENDERSPESIFIC:

                ap->encryption |= STD_WPA;
                
                //if it's vender specific tag, 
                //there is multicast cipher suite
                //it's not interesting part.
                offset = 4;

                break;
            }

            numUniCiperSuite = (bcbodyTags[8+offset]) + (bcbodyTags[9+offset] <<8);

            //get the start point of unicast cipher suite 
            u_int8_t * tagInfo = &bcbodyTags[10+offset];

            for(int32_t i=0; i<numUniCiperSuite; i++)
            {
                //get unicast cipher suite type
                switch (tagInfo[i * 4 + 3])
                {
                case 0x01:
                    ap->encryption |= ENC_WEP;
                    break;
                case 0x02:
                    ap->encryption |= ENC_TKIP;
                    break;
                case 0x03:
                    ap->encryption |= ENC_WRAP;
                    break;
                case 0x0A:
                case 0x04:
                    ap->encryption |= ENC_CCMP;
                    break;
                case 0x05:
                    ap->encryption |= ENC_WEP104;
                    break;
                case 0x08:
                case 0x09:
                    ap->encryption |= ENC_GCMP;
                    break;
                default:
                    break;
                }

            }//for(int32_t i=0; i<numUniCiperSuite; i++)


            numAKM = bcbodyTags[(10 + offset) + 4*numUniCiperSuite] + (bcbodyTags[(11 + offset) + 4 * numUniCiperSuite] << 8);
            
            //get start point of AKM suites
            tagInfo = tagInfo + 2 + 4*numUniCiperSuite;
 
            // Get the AKM suites
            for (int32_t i = 0; i < numAKM; i++)
            {
     
                switch (tagInfo[i * 4 + 3])
                {
                    case 0x01:
                        ap->encryption |= AUTH_MGT;
                        break;
                    case 0x02:

                        ap->encryption |= AUTH_PSK;
                        break;
                }
            }
            
        }//if ( (type == BEACONTAG_VENDERSPESIFIC && length >= 8 && (memcmp(bcbodyTags + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == BEACONTAG_RSNIE))
        

        bcbodyTags += length + 2;

    }//while (bcbodyTags < packet + packetLen)
	


}


void Airodump::getRadiotapInfo(struct radiotap * radiotapHeader, RadioTapInfo * rt)
{
    u_int32_t count = 1;

    //count the radiotap header
    for(u_int32_t * rdcount = (u_int32_t *)&(radiotapHeader->it_present); (*rdcount) & (1 << IEEE80211_RADIOTAP_EXT); rdcount ++)
    {
        count ++;
    }

    //get start point
    u_int8_t * ptr = (u_int8_t *)&(radiotapHeader->it_present) + 4*count;
    u_int32_t * it_present = (u_int32_t *)&radiotapHeader->it_present;
    
    //get header info
    for(u_int32_t i =0; i<count; i++)
    { 
        //just add pointer which is not interested
        for(u_int32_t flagbit = 0; flagbit<32; flagbit++)
        {
            if(!(*it_present & (1 << flagbit)))
                continue;

            switch(flagbit)
            {
            case IEEE80211_RADIOTAP_TSFT:
                ptr += 8;
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                ptr += 1;
                break;

            case IEEE80211_RADIOTAP_RATE:
                ptr += 1;
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
            {    
                struct radiotap_channel * channel = (struct radiotap_channel *)ptr;
                rt->channel = (channel->frequency - 2412)/5 +1;
                ptr += sizeof(struct radiotap_channel);
                break;
            }

            case IEEE80211_RADIOTAP_FHSS:
                ptr += 2;
                break;

            //average??????????
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                
                rt->pwr = (int32_t)((int8_t)(*ptr));

                //maybe alignment
                ptr += 2;    
                break;

            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                ptr += 1;
                break;

            case IEEE80211_RADIOTAP_LOCK_QUALITY:
                ptr +=2;
                break;

            case IEEE80211_RADIOTAP_TX_ATTENUATION :
                ptr +=2;
                break;

            case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
                ptr += 2;
                break;

            case IEEE80211_RADIOTAP_DBM_TX_POWER:
                ptr += 1;;
                break;

            case IEEE80211_RADIOTAP_ANTENNA:
                ptr += 1;
                break;

            case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                ptr += 1;
                break;
            
            case IEEE80211_RADIOTAP_DB_ANTNOISE:
                ptr +=1;
                break;
            
            case IEEE80211_RADIOTAP_RX_FLAGS:
                ptr +=2;
                break;
            
            case IEEE80211_RADIOTAP_TX_FLAGS:
                ptr +=2;
                break;
            case IEEE80211_RADIOTAP_RTS_RETRIES:
                ptr +=1;
                break;
            
            case IEEE80211_RADIOTAP_DATA_RETRIES:
                ptr +=1;
                break;

            /////////////////////no 18
            case IEEE80211_RADIOTAP_MCS:
                ptr +=3;
                break;
            
            case IEEE80211_RADIOTAP_AMPDU_STATUS:
                ptr +=8;
                break;

            case IEEE80211_RADIOTAP_VHT:
                ptr +=12;
                break;

            case IEEE80211_RADIOTAP_TIMESTAMP:
                ptr +=12;
                break;

            ///////////////////////////23
            ///////////////////////////24
            ///////////////////////////25
            ///////////////////////////26
            ///////////////////////////27
            ///////////////////////////28

            case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
                
                //???????????

                break;
            case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
                ptr +=6;
                break;

            case IEEE80211_RADIOTAP_EXT:
                //???
                break;

            } // switch(flagbit)
            
        } //for(u_int32_t flagbit = 0; flagbit<32; flagbit++)

        //see next flag
        it_present ++;


    }// for(u_int32_t i =0; i<count; i++)

}

