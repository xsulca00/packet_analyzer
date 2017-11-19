#pragma once

#include <string>
#include <utility>

namespace packet_analyzer::layer4 {
    using namespace std;

    string PacketLayer4(const uint8_t* packetL4, int packetType, size_t packetLen);
}
