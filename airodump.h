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
    Subscriber * subBeacon;
    Subscriber * subData;

public:


   
    //Subscriber *subProbe;


    Airodump(uint8_t * );
    void start();

    //print like real airodump
    void printAll();
    void printAP();
    void printProbe();
    

    //get packet from box and update
    void updateAP(u_int8_t * );
    void updateData(u_int8_t * );

    /////////
    void addNewAP();


    Apinfo * getAP(macaddr , u_int8_t * , u_int32_t );



    // monitoring thread
    void manageSubBox(Subscriber * sub);
    
    //filtering function for sniffer
    static bool filterBeacon(const u_int8_t * );
    static bool filterData(const u_int8_t * );





};