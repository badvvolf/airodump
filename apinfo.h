#pragma once
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "typedef.h"

class Apinfo{

public:

  
    macaddr bssid;
    int32_t pwr;
    int32_t pwrcount;

    u_int32_t beacons;
    u_int32_t data;
    u_int16_t channel;
    u_int32_t essidLen;
    u_int8_t * essid;
    u_int32_t encryption;

    Apinfo();
    ~Apinfo();

    void printAPInfo();

};  
