#pragma once
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "typedef.h"

class Apinfo{

public:

   // u_int8_t bssid[6];
    macaddr bssid;
    int32_t pwr;
    u_int32_t beacons;
    u_int32_t data;
    u_int16_t channel;
    u_int32_t essidLen;
    u_int8_t * essid;
    u_int8_t encryption;

    void printAPInfo();
    static Apinfo * getRadiotapInfo(struct radiotap * radiotapHeader);
    
};  
