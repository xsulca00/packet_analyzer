#include <iostream>
#include <string>

#include "utils.h"
#include "arguments.h"
#include "pcap_ptr.h"

int main(int argc, char* argv[]) {
    using namespace PacketAnalyzer;
    using namespace std;

    try {
        Arguments::Parser ap {argc, argv, "ha:s:l:f:"};

        if (Arguments::print_help(ap.get<string>("-h"))) return 1; 

        // typed options
        for (const auto& s : ap.args())
            if (!s.second.empty())
                cout << s.first << " : " << s.second << '\n';

        // file names
        for (const auto& s : ap.files())  {
            PCAP::PcapPtr pcap {s};
            cout << s << '\n';
        }
    } catch (Arguments::Parser::BadArgsStructure) {
        // no message because getopt writes error by itself
        return 2;
    } catch (Arguments::Parser::BadArgsNum) {
        cerr << "Invalid arguments count!\n";
        return 3;
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
