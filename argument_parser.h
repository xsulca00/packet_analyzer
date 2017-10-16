#pragma once

extern "C" {
#include <unistd.h>
}

#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>

#include "utils.h"

namespace PacketAnalyzer { namespace Arguments {
    using namespace std;

    class Parser {
    public:
        // expcetion class
        class BadArgsStructure {};
        class BadArgsNum {};

        Parser(int argc, char* argv[], const char* arguments) {
            if (argc <= 1) throw BadArgsNum{};

            // process options
            for (int c {getopt(argc, argv, arguments)}; c != -1; c = getopt(argc, argv, arguments)) {
                switch(c) {
                    case 'h': options["-h"] = help; break;
                    case 'a': options["-a"] = optarg; break;
                    case 's': options["-s"] = optarg; break;
                    case 'l': options["-l"] = optarg; break;
                    case 'f': options["-f"] = optarg; break;
                    default: throw BadArgsStructure{};
                }
            }

            // process file names
            for(int i {optind}; i != argc; ++i)
                fileNames.emplace_back(argv[i]);
        }

        const unordered_map<string, string>& args() const { return options; }

        template<typename T>
        T get(const string& o) { return Utils::to<T>(options[o]); }

        const vector<string>& files() const { return fileNames; }
    private:
        static constexpr auto help =
            "Usage:\n"
            "isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...\n"
            "-h                     Vypíše nápovědu a ukončí program.\n"
            "-a aggr-key            Zapnutí agregace podle klíče aggr-key:\n"
            "                           srcmac značící zdrojovou MAC adresu\n"
            "                           dstmac značící cílovou MAC adresu\n"
            "                           srcip značící zdrojovou IP adresu\n"
            "                           dstip značící cílovou IP adresu\n"
            "                           srcport značící číslo zdrojového transportního portu\n"
            "                           dstport značící číslo cílového transportního portu\n"
            "-s sort-key            Zapnutí řazení podle klíče sort-key,\n"
            "                       což může být packets (počet paketů) nebo bytes (počet bajtů).\n"
            "                       Řadit lze jak agregované tak i neagregované položky.\n"
            "                       Ve druhém případě je klíč packets bez efektu,\n"
            "                       protože všechny položky obsahují pouze jeden paket.\n"
            "                       Řadí se vždy sestupně.\n"
            "-l limit               Nezáporné celé číslo v desítkové soustavě\n"
            "                       udávající limit počtu vypsaných položek.\n"
            "-f filter-expression   Program zpracuje pouze pakety,\n"
            "                       které vyhovují filtru danému řetězcem filter-expression\n"
            "file                   Cesta k souboru ve formátu pcap (čitelný knihovnou libpcap).\n"
            "                       Možné je zadat jeden a více souborů.\n";

        unordered_map<string, string> options;
        vector<string> fileNames;
    };

    bool print_help(const string& msg) {
        if (!msg.empty()) {
            cerr << msg << '\n';
            return true;
        }
        return false;
    }

}}
