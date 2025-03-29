#include "http_parser.hpp"

bool HttpParser::is_http_payload(const std::vector<char>& payload)
{
    std::string payload_str(payload.begin(), payload.end());
    std::string payload_lower = payload_str;
    std::transform(payload_lower.begin(), payload_lower.end(), payload_lower.begin(), ::tolower);

    if (payload_lower.contains("http") || 
        payload_lower.contains("get") || 
        payload_lower.contains("post") || 
        payload_lower.contains("put") || 
        payload_lower.contains("delete") || 
        payload_lower.contains("head") || 
        payload_lower.contains("options") || 
        payload_lower.contains("trace") || 
        payload_lower.contains("connect"))
    {
        return true;
    }
    return false;
}
