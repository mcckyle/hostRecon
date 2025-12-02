//****************************************************************************************
//
//    Filename:    hostReconLib.h
//    Author:      Kyle D. McColgan (Saint Louis, MO)
//    Date:        6 November 2025
//    Description: This file contains the function declarations for the network scanner.
//
//****************************************************************************************

#ifndef HOST_RECON_LIB_H
#define HOST_RECON_LIB_H

#include <pcap/pcap.h>
#include <netinet/in.h>

//****************************************************************************************

constexpr int MAX_HOSTS = 254;

//****************************************************************************************

struct CaptureContext
{
    pcap_t * captureSession = nullptr;
    pcap_t * sendSession = nullptr;
    in_addr destination{};
    bool result = false;

    CaptureContext() = default;
    CaptureContext(pcap_t * cap, pcap_t * send)
        : captureSession(cap), sendSession(send) {}
};

//****************************************************************************************

// Utility and validation.
bool isValidIPAddress(const char * ip) noexcept;
unsigned short computeChecksum(void * data, int length) noexcept;
void intToCharArray(int num, char * buffer) noexcept;
void filterSpecialChars(const char * address, char * filtered) noexcept;

// Host list management.
void copyAddr(char (*hostList)[16], const char * source, int index) noexcept;
bool inList(const char* address, char (*hostList)[16], int listSize) noexcept;
void displayHostList(char (*hostList)[16], int numHosts) noexcept;

// Core scanning logic.
bool pingSweep(char (&destination)[16], CaptureContext & context);
void getHosts(char (*hostList)[16], int & numHosts, CaptureContext & context);
void callBack(u_char * user, const pcap_pkthdr * header, const u_char * packet);

// Miscellaneous utilities.
bool resolveMAC(const char * targetIP, CaptureContext & context, uint8_t out_mac[6], int timeout_ms = 2000);
void openNetworkInterface();
void extractDeviceInfo(const u_char * packet, char (&source)[16], char(&destination)[16]);

//****************************************************************************************

#endif  // HOST_RECON_LIB_H
