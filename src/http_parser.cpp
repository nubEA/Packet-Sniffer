#include "http_parser.hpp"

#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>      // For string splitting (can be replaced with find)
#include <stdexcept>    // For runtime_error
#include <cctype>       // For isspace, tolower
#include <algorithm>    // For find_if_not, transform
#include <optional>
#include <cstring>      // For strncmp

// --- Helper Functions ---

std::string HttpParser::trim_whitespace(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
    auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
    return (start < end ? std::string(start, end) : std::string());
}

std::string HttpParser::to_lower(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lower_str;
}

// --- Public Static Methods ---

bool HttpParser::is_likely_http_payload(const std::vector<char>& payload) {
    if (payload.size() < 5) { // Need at least enough for "GET /" or "HTTP/"
        return false;
    }
    const char* data = payload.data();
    size_t len = payload.size();

    // Check for response start
    if (len >= 5 && strncmp(data, "HTTP/", 5) == 0) {
        return true;
    }
    // Check for request methods (common ones)
    const char* methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "TRACE ", "CONNECT "};
    for (const char* method : methods) {
        size_t method_len = strlen(method);
        if (len >= method_len && strncmp(data, method, method_len) == 0) {
            return true;
        }
    }
    return false;
}

std::optional<HttpParser::HTTPMessage> HttpParser::parse_http(const std::vector<char>& payload) {
    if (payload.empty()) {
        return std::nullopt; // No data to parse
    }

    // Convert payload to string - assumes text-based payload (like HTTP)
    // Be mindful of potential encoding issues if body isn't ASCII/UTF-8 compatible
    // Using iterators handles potential null bytes within the body correctly
    std::string http_data(payload.begin(), payload.end());

    try {
        // Determine if it's a request or response based on the start line
        if (http_data.rfind("HTTP/", 0) == 0) { // Check if starts with "HTTP/"
            return parse_response(http_data);
        } else {
            // Assume request otherwise (parse_request will validate method)
            return parse_request(http_data);
        }
    } catch (const std::runtime_error& e) {
        // Log error maybe? For now, return nullopt on parsing failure
        // std::cerr << "HTTP Parse Error: " << e.what() << std::endl;
        return std::nullopt;
    } catch (...) {
        // Catch any other unexpected exceptions during parsing
        return std::nullopt;
    }
}


// --- Private Static Methods ---

HttpParser::HTTPMessage HttpParser::parse_request(const std::string& data) {
    HTTPMessage msg;
    msg.isRequest = true;

    // Find end of first line (\r\n)
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) {
        throw std::runtime_error("HTTP Request: No CRLF found after request line");
    }
    std::string request_line = data.substr(0, line_end);

    // Parse Request Line (Method URL Version)
    size_t method_end = request_line.find(' ');
    if (method_end == std::string::npos) {
        throw std::runtime_error("HTTP Request: Malformed request line (no space after method)");
    }
    msg.method = request_line.substr(0, method_end);

    size_t url_end = request_line.find(' ', method_end + 1);
    if (url_end == std::string::npos) {
        // Handle HTTP/0.9 style request (Method URL - no version)
        msg.url = request_line.substr(method_end + 1);
        msg.version = "HTTP/0.9"; // Or leave empty, depends on desired behavior
    } else {
        msg.url = request_line.substr(method_end + 1, url_end - (method_end + 1));
        msg.version = trim_whitespace(request_line.substr(url_end + 1));
    }

    // Basic validation of method (add more methods if needed)
     const char* methods[] = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT"};
     bool method_found = false;
     for(const char* m : methods) {
         if(msg.method == m) {
             method_found = true;
             break;
         }
     }
     if (!method_found) {
          // Allow unrecognized methods, but maybe log a warning?
          // Or throw: throw std::runtime_error("HTTP Request: Unrecognized method: " + msg.method);
     }


    // Find end of headers (\r\n\r\n)
    size_t headers_end = data.find("\r\n\r\n", line_end + 2);
    if (headers_end == std::string::npos) {
        throw std::runtime_error("HTTP Request: Headers separator not found");
    }
    std::string header_block = data.substr(line_end + 2, headers_end - (line_end + 2));

    // Parse headers
    msg.headers = parse_headers(header_block);

    // Parse Body (Handle Content-Length)
    size_t body_start = headers_end + 4;
    auto content_length_it = msg.get_header_value("content-length"); // Use helper

    if (content_length_it) {
        try {
            size_t body_length = std::stoull(*content_length_it); // Use unsigned long long
            if (body_length > 0) {
                if (body_start + body_length > data.length()) {
                    // Content-Length exceeds available data - take what's there
                     size_t available_length = data.length() - body_start;
                     msg.body.assign(data.begin() + body_start, data.begin() + body_start + available_length);
                     // Consider logging a warning about truncation
                } else {
                    // Extract exact length
                     msg.body.assign(data.begin() + body_start, data.begin() + body_start + body_length);
                }
            }
            // else body_length is 0, body remains empty
        } catch (const std::invalid_argument& /*e*/) {
            throw std::runtime_error("HTTP Request: Invalid Content-Length value");
        } catch (const std::out_of_range& /*e*/) {
            throw std::runtime_error("HTTP Request: Content-Length value out of range");
        }
    }
    // Ignore Transfer-Encoding: chunked for now

    return msg;
}

HttpParser::HTTPMessage HttpParser::parse_response(const std::string& data) {
    HTTPMessage msg;
    msg.isRequest = false;

    // Find end of first line (\r\n)
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) {
        throw std::runtime_error("HTTP Response: No CRLF found after status line");
    }
    std::string status_line = data.substr(0, line_end);

    // Parse Status Line (Version StatusCode StatusText)
    size_t version_end = status_line.find(' ');
    if (version_end == std::string::npos) {
        throw std::runtime_error("HTTP Response: Malformed status line (no space after version)");
    }
    msg.version = status_line.substr(0, version_end);

    size_t code_end = status_line.find(' ', version_end + 1);
    if (code_end == std::string::npos) {
        throw std::runtime_error("HTTP Response: Malformed status line (no space after status code)");
    }
    std::string status_code_str = status_line.substr(version_end + 1, code_end - (version_end + 1));
    try {
        msg.statusCode = std::stoi(status_code_str);
    } catch (const std::invalid_argument& /*e*/) {
        throw std::runtime_error("HTTP Response: Invalid status code value");
    } catch (const std::out_of_range& /*e*/) {
        throw std::runtime_error("HTTP Response: Status code value out of range");
    }

    msg.statusText = trim_whitespace(status_line.substr(code_end + 1));


    // Find end of headers (\r\n\r\n)
    size_t headers_end = data.find("\r\n\r\n", line_end + 2);
    if (headers_end == std::string::npos) {
        throw std::runtime_error("HTTP Response: Headers separator not found");
    }
    std::string header_block = data.substr(line_end + 2, headers_end - (line_end + 2));

    // Parse headers
    msg.headers = parse_headers(header_block);

    // Parse Body (Handle Content-Length) - Same logic as request
    size_t body_start = headers_end + 4;
    auto content_length_it = msg.get_header_value("content-length"); // Use helper

    if (content_length_it) {
         try {
            size_t body_length = std::stoull(*content_length_it);
            if (body_length > 0) {
                 if (body_start + body_length > data.length()) {
                    size_t available_length = data.length() - body_start;
                    msg.body.assign(data.begin() + body_start, data.begin() + body_start + available_length);
                 } else {
                     msg.body.assign(data.begin() + body_start, data.begin() + body_start + body_length);
                 }
            }
        } catch (const std::invalid_argument& /*e*/) {
            throw std::runtime_error("HTTP Response: Invalid Content-Length value");
        } catch (const std::out_of_range& /*e*/) {
            throw std::runtime_error("HTTP Response: Content-Length value out of range");
        }
    }

    return msg;
}


std::unordered_map<std::string, std::string> HttpParser::parse_headers(
    const std::string& header_block)
{
    std::unordered_map<std::string, std::string> parsed_headers;
    size_t current_pos = 0;
    size_t next_crlf;

    while (current_pos < header_block.length()) {
        next_crlf = header_block.find("\r\n", current_pos);
        std::string line;
        if (next_crlf == std::string::npos) {
             // Take the rest of the string if no final CRLF (potentially lenient)
            line = header_block.substr(current_pos);
            current_pos = header_block.length(); // Exit loop
        } else {
            line = header_block.substr(current_pos, next_crlf - current_pos);
            current_pos = next_crlf + 2; // Move past CRLF
        }

        if (line.empty()) continue; // Skip empty lines if any

        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = trim_whitespace(line.substr(0, colon_pos));
            std::string value = trim_whitespace(line.substr(colon_pos + 1));

            if (!key.empty()) {
                // Store key lowercase for case-insensitive lookup
                parsed_headers[to_lower(key)] = value;
            }
        }
        // Ignore lines without a colon (malformed)
    }

    return parsed_headers;
}

// --- HTTPMessage Member Function ---

std::optional<std::string> HttpParser::HTTPMessage::get_header_value(const std::string& key) const {
    auto it = headers.find(to_lower(key)); // Search using lowercase key
    if (it != headers.end()) {
        return it->second; // Return the stored value (original case, trimmed)
    }
    return std::nullopt;
}