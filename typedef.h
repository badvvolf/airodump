#pragma once
#include <stdint.h>
#include <netinet/ether.h>
#include <mutex>



#define MACLEN 6


#define	IEEE80211_CAPINFO_PRIVACY		0x0010

#define	IEEE80211_FC0_TYPE_MASK			0x0c

#define	IEEE80211_FC0_TYPE_MGT			0x00
#define	IEEE80211_FC0_TYPE_DATA			0x08

#define	IEEE80211_FC0_SUBTYPE_MASK		0xf0
#define	IEEE80211_FC0_SUBTYPE_DATA		0x00
#define	IEEE80211_FC0_SUBTYPE_BEACON	0x80

#define STD_QOS 0x2000

#define STD_OPN 0x0001
#define STD_WEP 0x0002
#define STD_WPA 0x0004
#define STD_WPA2 0x0008


#define ENC_WEP 0x0010
#define ENC_TKIP 0x0020
#define ENC_WRAP 0x0040
#define ENC_CCMP 0x0080
#define ENC_WEP40 0x1000
#define ENC_WEP104 0x0100
#define ENC_GCMP 0x4000


#define AUTH_OPN 0x0200
#define AUTH_PSK 0x0400
#define AUTH_MGT 0x0800

#define BEACONTAG_RSNIE 0x30
#define BEACONTAG_VENDERSPESIFIC 0xDD


#pragma pack(push, 1)


using namespace std;

typedef array<u_int8_t, 6> macaddr;




struct radiotap_channel{

    u_int16_t frequency;
    u_int16_t flags;

};


struct beaconbody{

    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capability;

    //dynamic length, use pointer
    u_int8_t tags;

};


struct dot11{

    u_int16_t fc;
    u_int16_t duid;
    macaddr addr1;
    macaddr addr2;
    macaddr addr3;
    u_int16_t sc;

};

struct radiotap{

    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;

};



#pragma pack(pop)


enum ieee80211_radiotap_presence {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	/* 18 is XChannel, but it's not defined yet */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};