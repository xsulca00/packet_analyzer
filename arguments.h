#pragma once

extern "C" {
#include <unistd.h>
}

#include <iostream>
#include <unordered_map>
#include <string>
#include <map>
#include <vector>

#include "utils.h"

namespace packet_analyzer::parameters {
    using namespace std;

    // pair -> {packets, bytes}
    using AggrInfo = pair<size_t, size_t>;

    extern map<string, AggrInfo> aggregationsStatistics;

    void addAggr(const string& key, size_t size);

    struct Arguments {
        string help;
        string aggregation;
        string sortBy;
        string filter;
        string limit;
    };

    // program arguments passed via console
    extern Arguments arguments;

    class ArgumentParser {
    public:
        ArgumentParser() = default;
        ArgumentParser(int argc, char* argv[], const char* getoptstr);

        bool IsSet(const string& s) { 
            const auto& o = arguments[s];
            if (o.empty()) return false;
            return true;
        }

        unordered_map<string, string> arguments;
        vector<string> files;
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
            "                       Možné je zadat jeden a více souborů.";

    };

    // parsing program arguments
    extern ArgumentParser argumentsParser;

    string CheckAggrKey(const string& s);
    string CheckSortKey(const string& s);
    string CheckLimit(const string& s);
    string CheckFilter(const string& s);
}
