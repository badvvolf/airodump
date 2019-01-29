#pragma once

#include <map>
#include "apinfo.h"
#include "typedef.h"
#include "sniffer.h"
#include <thread>

using namespace std;

typedef multimap<macaddr, Apinfo *>::iterator apmapItor;

class Airodump{

private:

    multimap<macaddr, Apinfo * > apInfoMap;

    //have probe info
    Sniffer * sniffer;

public:


    Subscriber *subBeacon;
    //Subscriber *subProbe;


    Airodump(uint8_t * );
    void start();

    //print like real airodump
    void printAll();
    void printAP();
    void printProbe();
    

    //get packet from box and update data
    void updateAP(const u_int8_t * packet);

    /////////
    void addNewAP();


    Apinfo *  getAP(macaddr bssid, u_int8_t * essid, u_int32_t essidLen);



    // monitoring thread
    void checkBeaconSubBox();
    void checkProbeSubBox();

    //filtering function for sniffer
    static bool filterBeacon(const u_int8_t * packet);





};