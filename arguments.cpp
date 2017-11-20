#include <utility>
#include <unordered_map>
#include <map>

#include "arguments.h"
#include "utils.h"

namespace packet_analyzer::parameters {
    map<string, AggrInfo> aggregationsStatistics;
    Arguments arguments;
    ArgumentParser argumentsParser;

    ArgumentParser::ArgumentParser(int argc, char* argv[], const char* getoptstr) {
        const char* helpToPrint =
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

        if (argc <= 0) throw runtime_error{"ArgumentParser: argc <= 0 !"};

        // process arguments
        int c;
        while ((c = getopt(argc, argv, getoptstr)) != -1) {
            switch(c) {
                case 'f': arguments["f"] = optarg; break;
                case 'h': arguments["h"] = helpToPrint; break;
                case 's': arguments["s"] = CheckSortKey(optarg); break;
                case 'l': arguments["l"] = CheckLimit(optarg); break;
                case 'a': arguments["a"] = CheckAggrKey(optarg); break;
                default: throw runtime_error {"Invalid option!"};
            }
        }

        // process file names
        for(int i = optind; i < argc; ++i)
            files.emplace_back(argv[i]);

        if (arguments["h"].empty() && files.empty()) throw runtime_error{"No files!"};
    }
    
    string CheckAggrKey(const string& s) {
        if (s == "srcmac") return s;
        if (s == "dstmac") return s;
        if (s == "srcip") return s;
        if (s == "dstip") return s;
        if (s == "srcport") return s;
        if (s == "dstport") return s;

        throw runtime_error{"Invalid AggrKey: " + s};
    }

    string CheckSortKey(const string& s) {
        if (s == "packets") return s;
        if (s == "bytes") return s;

        throw runtime_error{"Invalid SortKey: " + s};
    }

    string CheckLimit(const string& s) {
        try { 
            utils::to<unsigned>(s); 
        } catch(const runtime_error&) { 
            throw runtime_error {"Invalid value of limit: " + s}; 
        }

        if (!s.empty())
            if (s.front() == '-') 
                throw runtime_error{"Limit value is < 0 !"};

        return s;
    }

    void addAggr(const string& key, size_t size) {
        auto& p = aggregationsStatistics[key];
        p.first += 1;
        p.second += size;
    }
}
