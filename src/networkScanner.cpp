//****************************************************************************************
//
//    Filename:    networkScanner.cpp
//    Author:      Kyle D. McColgan (Saint Louis, MO)
//    Date:        6 November 2025
//    Description: A simple C++17 libpcap-based host scanner.
//
//****************************************************************************************

#include "hostReconLib.h"
#include <iostream>

using namespace std;

//****************************************************************************************

int main()
{
    constexpr int TIMEOUT_MS = 2000; //Timeout value in milliseconds.
    char hostList [MAX_HOSTS][16]{}; //Assuming each IP stored in a 16-character array.
    int numHosts = 0;

    char sendError [PCAP_ERRBUF_SIZE]{};
    char capError [PCAP_ERRBUF_SIZE]{};
    const char * iface = "enp34s0";

    pcap_t * captureSession = nullptr;
    pcap_t * sendSession = nullptr;

    cout << "hostRecon - libpcap-based network scanner\n"
         << "-----------------------------------------\n";

    //Initalize the network session handlers...
    cout << "Initializing the network interfaces...\n";
    sendSession = pcap_open_live(iface, BUFSIZ, 1, TIMEOUT_MS, sendError);
    captureSession = pcap_open_live(iface, BUFSIZ, 1, TIMEOUT_MS, capError);

    if ( ( ! sendSession) || ( ! captureSession) )
    {
        cerr << "[ERROR] Failed to initalize pcap sessions.\n";

        if (sendSession)
        {
            pcap_close(sendSession);
        }

        return 1;
    }

    pcap_setdirection(captureSession, PCAP_D_INOUT);
    cout << "[OK] interfaces initialized successfully!\n";

    //Set the packet filter...
    bpf_program filter;
    const char filterExp[] = "arp or icmp";
    cout << "Applying filters...\n";
    //bpf_u_int32 net = 0, mask = 0;

    // if (pcap_lookupnet(iface, &net, &mask, capError) == -1)
    // {
    //     //Not fatal error...continue with net = 0.
    //     net = 0;
    // }

    //Set the filter for ICMP packets
    // char filterExp[] = "icmp[icmptype] == icmp-echoreply";
    // char filterExp[] = "icmp and icmp[icmptype] == 0";
    //char filterExp[] = "icmp[icmpcode] == 0 and icmp[icmptype] == 0";

    if (pcap_compile(captureSession, &filter, filterExp, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(captureSession, &filter) == -1)
    {
        cerr << "[ERROR] Failed to set filter: " << pcap_geterr(captureSession) << '\n';

        pcap_close(sendSession);
        pcap_close(captureSession);

        return 1;
    }

    cout << "[OK] Capture filter applied.\n";

    //Begin scan.
    CaptureContext context(captureSession, sendSession);
    cout << "\nScanning 192.168.1.1 - 192.168.1.254...\n";
    getHosts(hostList, numHosts, context);

    cout << "\nScan complete.\n";
    displayHostList(hostList, numHosts);

    //Cleanup.
    cout << "\nCleaning up...\n";
    pcap_freecode(&filter);
    pcap_close(captureSession);
    pcap_close(sendSession);

    cout << "[OK] Done.\n";

    return 0;
}

//****************************************************************************************
// std::cout << " _               _   ____                          \n";
// std::cout << "| |__   ___  ___| |_|  _ \\ ___  ___ ____   _____  \n";
// std::cout << "| '_ \\/ _ \\/ __| __| |_) / _ \\/ __/ _ \\| '_ \\ \n";
// std::cout << "| | | | (_) \\__ \\ |_|  _ <  __/ (_| (_) |  | | | \n";
// std::cout << "|_| |_|\\___/|___/\\__|_| \\_\\___|\\____/\\_|_| |_| \n";
// Sample output below...
/*
 * hostRecon - libpcap-based network scanner
 * -----------------------------------------
 * Initializing the network interfaces...
 * [OK] interfaces initialized successfully!
 * Applying filters...
 * [OK] Capture filter applied.
 *
 * Scanning 192.168.1.1 - 192.168.1.254...
 * [INFO] Resolving MAC for: 192.168.1.1...
 * [WARN] Failed to resolve the MAC address for: 192.168.1.1. Skipping host.
 *
 * ...
 *
 *
 * [INFO] Resolving MAC for: 192.168.1.253...
 * [OK] MAC address resolved for: 192.168.1.253: A0:72:2C:67:88:94
 * ***Pinging 192.168.1.253...
 * Reply from 192.168.1.253
 * Destination 192.168.1.253 is active!
 *
 * [INFO] Host list updated.
 * [INFO] Resolving MAC for: 192.168.1.254...
 * [OK] MAC address resolved for: 192.168.1.254: BC:9A:8E:20:22:F1
 * ***Pinging 192.168.1.254...
 * Host 192.168.1.254 is inactive.
 *
 * Scan complete.
 *
 * Active Hosts (13):
 * 1. 192.168.1.94
 * 2. 192.168.1.100
 * 3. 192.168.1.102
 * 4. 192.168.1.103
 * 5. 192.168.1.201
 * 6. 192.168.1.205
 * 7. 192.168.1.224
 * 8. 192.168.1.225
 * 9. 192.168.1.228
 * 10. 192.168.1.235
 * 11. 192.168.1.245
 * 12. 192.168.1.246
 * 13. 192.168.1.253
 * ---------------------------------
 *
 * Cleaning up...
 * [OK] Done.
 *
*/
