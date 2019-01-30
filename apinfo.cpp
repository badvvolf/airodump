
#pragma once
#include "apinfo.h"




Apinfo::Apinfo()
{
    bssid = {0, };
    pwr = 0;
    pwrcount =0;
    beacons = 0;
    data = 0;
    channel = 0;
    essidLen = 0;
    essid = NULL;
    encryption = 0;
 
}

Apinfo::~Apinfo()
{

    delete(essid);
}


void Apinfo::printAPInfo()
{
    Util util;
    util.printMACAddr(bssid);  
  
    printf("|%d|%d|%d|   |%d|  |", pwr/pwrcount, beacons, data , channel);  
        
    if ((encryption & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2))== 0)
        printf("    ");
    else if (encryption & STD_WPA2)
        printf("WPA2");
    else if (encryption & STD_WPA)
        printf("WPA ");
    else if (encryption & STD_WEP)
        printf("WEP ");
    else if (encryption & STD_OPN)
        printf("OPN");
    
    printf("|");

    if ((encryption
        & (ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP104
        | ENC_WEP40
        | ENC_GCMP))
        == 0)
        printf("       ");
    else if (encryption & ENC_CCMP)
        printf("CCMP");
    else if (encryption & ENC_WRAP)
        printf("WRAP");
    else if (encryption & ENC_TKIP)
        printf("TKIP  ");
    else if (encryption & ENC_WEP104)
        printf("WEP104");
    else if (encryption & ENC_WEP40)
        printf("WEP40  ");
    else if (encryption & ENC_WEP)
        printf("WEP    ");
    else if (encryption & ENC_GCMP)
        printf("GCMP   ");

    printf("|");
			
    if (( encryption & (AUTH_OPN | AUTH_PSK | AUTH_MGT)) == 0)
        printf("   ");
    else if (encryption & AUTH_MGT)
        printf("MGT");
    else if (encryption & AUTH_PSK)
    {
       
        if (encryption & STD_WEP)
            printf("SKA");
        else
            printf("PSK");
    }
    else if (encryption & AUTH_OPN)
        printf("OPN");


    printf("|");
    

   
    if(essidLen !=0)
       printf("%s", essid);
    else
    {
        printf("<len %d>", essidLen);
    }
    
    
    printf("\n");

}
