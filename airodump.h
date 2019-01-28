#pragma once

#include <map>
#include "apinfo.h"
#include "typedef.h"
#include <list>  
#include <string.h>
#include <stdlib.h>
#include <algorithm>

using namespace std;

typedef multimap<macaddr, Apinfo *>::iterator apmapItor;

class Airodump{

    // have multimap of ap info
    // mac - apinfo pair
    multimap<macaddr, Apinfo * > apInfoMap;
    
    //have list of probe info

    //subscribe box
    void * box;

public:
    
    //print like real airodump
    void printAll();

    void printAPList();
    void printProbeList();

    //get packet from box and change it to ApInfo
    void updateAP(const u_int8_t * packet);

    void addNewAP();

    Apinfo *  getAP(macaddr bssid, u_int8_t * essid, u_int32_t essidLen);



};