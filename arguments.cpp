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
        if (argc <= 0) throw runtime_error{"ArgumentParser: argc <= 0 !"};

        // process arguments
        for (int c {getopt(argc, argv, getoptstr)}; c != -1; c = getopt(argc, argv, getoptstr)) {
            switch(c) {
                case 'h': arguments["h"] = help; break;
                case 'a': arguments["a"] = CheckAggrKey(optarg); break;
                case 's': arguments["s"] = CheckSortKey(optarg); break;
                case 'l': arguments["l"] = CheckLimit(optarg); break;
                case 'f': arguments["f"] = optarg; break;
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
        ++p.first;
        p.second += size;
    }
}
