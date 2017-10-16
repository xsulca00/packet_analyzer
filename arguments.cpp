#include <utility>

#include "arguments.h"
#include "utils.h"

namespace PacketAnalyzer { namespace Arguments {
    Parser::Parser(int argc, char* argv[], const char* arguments) {
        if (argc <= 1) throw BadArgsNum{};

        // process options
        for (int c {getopt(argc, argv, arguments)}; c != -1; c = getopt(argc, argv, arguments)) {
            switch(c) {
                case 'h': options["-h"] = help; break;
                case 'a': options["-a"] = aggr_key(optarg); break;
                case 's': options["-s"] = sort_key(optarg); break;
                case 'l': options["-l"] = limit(optarg); break;
                case 'f': options["-f"] = filter_expression(optarg); break;
                default: throw BadArgsStructure{};
            }
        }

        // process file names
        for(int i {optind}; i != argc; ++i)
            fileNames.emplace_back(argv[i]);
    }
    
    string Parser::aggr_key(const string& s) const {
        if (s == "srcmac"  || s == "dstmac" ||
            s == "srcip"   || s == "dstip"  ||
            s == "srcport" || s == "dstport") { 
            return s;
        }

        throw runtime_error{"Invalid aggr-key: " + s};
    }

    string Parser::sort_key(const string& s) const {
        if (s == "packets"  || s == "bytes") return s;

        throw runtime_error{"Invalid sort-key: " + s};
    }

    string Parser::limit(const string& s) const {
        try { Utils::to<unsigned>(s); } catch(const runtime_error&) { throw runtime_error {"Invalid limit number: " + s}; }

        return s;
    }

    string Parser::filter_expression(const string& s) const {
        // TODO: check filter syntax
        return s;
    }

    bool print_help(const string& msg) {
        if (!msg.empty()) {
            cerr << msg << '\n';
            return true;
        }
        return false;
    }
}}
