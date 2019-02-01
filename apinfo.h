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


class ProbeInfo{

public:
    macaddr bssid;
    macaddr station;
    
    int32_t pwr;
    int32_t pwrcount;

    int32_t rate;
    u_int32_t lost;

    u_int32_t frame;
    
    u_int32_t essidLen;
    u_int8_t * essid;

    ProbeInfo();
    ~ProbeInfo();

    void printPIInfo();
};



class RadioTapInfo{

public:

    int32_t pwr;

    u_int16_t channel;


};