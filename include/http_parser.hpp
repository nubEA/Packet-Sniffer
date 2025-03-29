#ifndef HTTP_PARSER_HPP
#define HTTP_PARSER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <optional> // Use optional for potentially failing parse

// Forward declaration if packet_structure.hpp is not strictly needed here
// #include "packet_structure.hpp" // Only if HTTPMessage needs types from it

class HttpParser {
public:
    struct HTTPMessage {
        bool isRequest = false; // True if HTTP request, false if response
        std::string method;     // HTTP method (GET, POST, etc.) - original case
        std::string url;        // Requested URL - original case
        std::string version;    // HTTP version (e.g., HTTP/1.1) - original case
        int statusCode = 0;     // Status code (for responses)
        std::string statusText; // Status text (for responses) - original case, trimmed
        // Header keys are stored lowercase for case-insensitive lookup
        // Header values are stored in original case, but trimmed
        std::unordered_map<std::string, std::string> headers;
        std::vector<char> body; // Store body as bytes

        // Helper for case-insensitive header lookup
        std::optional<std::string> get_header_value(const std::string& key) const;
    };

    // Basic check if payload *might* be HTTP (checks start)
    static bool is_likely_http_payload(const std::vector<char>& payload);

    // Main parsing function, returns optional in case of parse failure
    static std::optional<HTTPMessage> parse_http(const std::vector<char>& payload);

private:
    // Parsing functions throw std::runtime_error on failure
    static HTTPMessage parse_request(const std::string& data);
    static HTTPMessage parse_response(const std::string& data);

    // Helper to parse header block into a map (keys lowercase)
    static std::unordered_map<std::string, std::string> parse_headers(
        const std::string& header_block);

    // Helper function to trim whitespace
    static std::string trim_whitespace(const std::string& str);

    // Helper function for lowercase conversion
    static std::string to_lower(const std::string& str);
};

#endif // HTTP_PARSER_HPP