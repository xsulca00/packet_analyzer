#pragma once

#include <string>
#include <utility>

namespace packet_analyzer::layer4 {
    using namespace std;

    string Layer4(const uint8_t* packetL4, int type, size_t size);

    enum TcpFlagTypes { CWR = (1 << 7), 
                        ECE = (1 << 6), 
                        URG = (1 << 5), 
                        ACK = (1 << 4), 
                        PSH = (1 << 3), 
                        RST = (1 << 2), 
                        SYN = (1 << 1), 
                        FIN = (1 << 0)};

    string TCPFlags(uint8_t flags);
}
