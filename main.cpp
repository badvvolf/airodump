
#include <stdio.h>
#include "airodump.h"
#include <thread>

//to do
// - implement
//      specific crypto 
//      data frame 
// - refactoring
//      sniffer : find subscriber... -> multiple subscriber

void usage();

int main(int argc, char* argv[]) 
{

    if (argc != 2) 
    {
        usage();
        return -1;
    }

    uint8_t * dev = (uint8_t * )argv[1];
    
    Airodump * airodump = new Airodump(dev);
    thread startAirodump(&Airodump::start, airodump);
    startAirodump.join();

} //int main(int argc, char* argv[]) 


void usage() 
{
  printf("syntax: airodump <interface>\n");
  printf("sample: airodump wlan0\n");

} //void usage() 


