#ifndef HTTP_PARSER_HPP
#define HTTP_PARSER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include "packet_structure.hpp"
#include <algorithm>

class HttpParser {
public:
    struct HTTPMessage {
        bool isRequest = false; // True if HTTP request, false if response
        std::string method;     // HTTP method (GET, POST, etc.)
        std::string url;        // Requested URL
        std::string version;    // HTTP version (e.g., HTTP/1.1)
        int statusCode = 0;     // Status code (for responses)
        std::string statusText; // Status text (for responses)
        std::unordered_map<std::string, std::string> headers; // Parsed headers
        std::string body;       // HTTP body (optional)
    };

    static bool is_http_payload(const std::vector<char>& payload);
    static HTTPMessage parse_http(const std::vector<char>& payload);
    
private:
    static HTTPMessage parse_request(const std::string& data);
    static HTTPMessage parse_response(const std::string& data);
    static std::unordered_map<std::string, std::string> parse_headers(const std::vector<std::string>& lines);
};

#endif // HTTP_PARSER_HPP
