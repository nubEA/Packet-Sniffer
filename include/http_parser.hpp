#ifndef HTTP_PARSER_HPP
#define HTTP_PARSER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

class HttpParser {
public:
    struct HTTPMessage {
        bool isRequest = false;
        std::string method;
        std::string url;
        std::string version;
        int statusCode = 0;
        std::string statusText;
        std::unordered_map<std::string, std::string> headers;
        std::vector<char> body;

        std::optional<std::string> get_header_value(const std::string& key) const;
    };

    static bool is_likely_http_payload(const std::vector<char>& payload);
    //optional in case of parsing failure
    static std::optional<HTTPMessage> parse_http(const std::vector<char>& payload);

private:
    static HTTPMessage parse_request(const std::string& data);
    static HTTPMessage parse_response(const std::string& data);
    static std::unordered_map<std::string, std::string> parse_headers(
        const std::string& header_block);
    static std::string trim_whitespace(const std::string& str);
    static std::string to_lower(const std::string& str);
};

#endif // HTTP_PARSER_HPP