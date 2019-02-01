#pragma once

#include <map>
#include "apinfo.h"
#include "typedef.h"
#include "sniffer.h"
#include <thread>

using namespace std;

typedef multimap<macaddr, Apinfo *>::iterator apmapItor;

typedef multimap<macaddr, ProbeInfo *>::iterator pimapItor;



class Airodump{

private:

    multimap<macaddr, Apinfo * > apInfoMap;
    multimap<macaddr, ProbeInfo * > piInfoMap;
    //have probe info
    Sniffer * sniffer;
    Subscriber * subBeacon;
    Subscriber * subData;
    Subscriber * subProbeReq;

public:


   
    //Subscriber *subProbe;


    Airodump(uint8_t * );
    void start();

    //print like real airodump
    void printAll();
    void printAP();
    void printProbe();
    

    //get packet from box and update
    void updateAP(SubBoxContent * );
    void updateData(SubBoxContent * );
    void updateProbeReq(SubBoxContent *);
    
    /////////
    // void addNewAP();


    Apinfo * getAP(macaddr , u_int8_t * , u_int32_t );
    void getRadiotapInfo(struct radiotap * , RadioTapInfo * );
    void getCrypto(u_int8_t * , struct beaconbody *  , u_int32_t , Apinfo * );

    ProbeInfo * getPI(macaddr , macaddr, u_int8_t * , u_int32_t );

    // monitoring thread
    void manageSubBox(Subscriber * );
    
    //filtering function for sniffer
    static bool filterBeacon(const u_int8_t * );
    static bool filterData(const u_int8_t * );
    static bool filterProbeReq(const u_int8_t * packet);




};