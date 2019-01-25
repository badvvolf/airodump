
#pragma once
#include "apinfo.h"

void Apinfo::printAPInfo()
{
    Util util;
    util.printMACAddr(bssid);  
    printf(" | %d  |  %d  |   %d  |   |  %d  |  | ", pwr/(int32_t)beacons, beacons, data , channel);  
        
    if(!encryption)
        printf("OPN");
    // else

    printf(" |   |  | ");
    
    printf("%s \n", essid);

}

Apinfo * Apinfo::getRadiotapInfo(struct radiotap * radiotapHeader)
{

    //to check all radiotap header
    Apinfo * ap = new Apinfo();
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
                ap->channel = (channel->frequency - 2412)/5 +1;
                ptr += sizeof(struct radiotap_channel);
                break;
            }

            case IEEE80211_RADIOTAP_FHSS:
                ptr += 2;
                break;

            //average??????????
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                
                ap->pwr = (int8_t)(*ptr);
                
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
            
        }

        //see next flag
        it_present ++;


    }// for(u_int32_t i =0; i<count; i++)

    return ap;

}