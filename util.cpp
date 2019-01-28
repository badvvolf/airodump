#pragma one
#include "util.h"


void Util::printMACAddr(macaddr addr)
{
    int i = 0;
    for(i= 0; i<MACLEN; i++)
    {
        printf("%02x", addr[i]);
        if(i < MACLEN-1)
            printf(":");
    }

} //Util::void printMACAddr(u_int8_t * addr)
