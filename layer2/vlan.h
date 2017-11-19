#pragma once

#include <string>
#include <utility>

namespace packet_analyzer::layer2 {
    using namespace std;

    struct HeaderVLAN {
        struct Tci {
            unsigned vid    :12;
            bool     dei    :1;
            unsigned pcp    :3;
        } __attribute__((packed)) tci;
        uint16_t tpid;
    } __attribute__((packed));
     
    string InfoVLAN(const uint8_t* packet);
    pair<const uint8_t*, int> SkipVLAN(const uint8_t* packet);
}
