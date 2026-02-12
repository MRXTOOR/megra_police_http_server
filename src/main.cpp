#ifdef __linux__

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr int SERVER_PORT = 1616;
constexpr std::size_t MAX_REQUEST_SIZE = 50 * 1024 * 1024; // 50 MB
constexpr int LISTEN_BACKLOG = 10;
constexpr std::size_t READ_BUFFER_SIZE = 4096;
constexpr int MAX_RETRIES = 3;
} // anonymous namespace

// RAII Socket wrapper
class Socket {
public:
    explicit Socket(int fd = -1) : fd_(fd) {}
    
    ~Socket() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }
    
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    
    Socket(Socket&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            if (fd_ != -1) {
                ::close(fd_);
            }
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    
    int get() const { return fd_; }
    int release() {
        int temp = fd_;
        fd_ = -1;
        return temp;
    }
    
    bool is_valid() const { return fd_ != -1; }
    
    void reset(int new_fd = -1) {
        if (fd_ != -1) {
            ::close(fd_);
        }
        fd_ = new_fd;
    }
    
private:
    int fd_;
};

struct HttpRequest {
  std::string Method;
  std::string Path;
  std::string Version;
  std::map<std::string, std::string> Headers;
  std::string Body;
};

// Security: Safer path validation
bool IsValidFileName(const std::string& filename) {
    if (filename.empty() || filename.size() > 255) {
        return false;
    }
    
    // Check for path traversal attempts
    if (filename.find("..") != std::string::npos ||
        filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos) {
        return false;
    }
    
    // Check for dangerous characters
    const std::string dangerous_chars = "<>:\"|?*\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    if (filename.find_first_of(dangerous_chars) != std::string::npos) {
        return false;
    }
    
    return true;
}

std::string ToLower(const std::string &text) {
    std::string result;
    result.reserve(text.size());
    
    for (unsigned char ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            result.push_back(static_cast<char>(ch - 'A' + 'a'));
        } else {
            result.push_back(static_cast<char>(ch));
        }
    }
    return result;
}

bool IsRunningAsRoot() {
#ifdef __linux__
  uid_t UserId = getuid();
  return UserId == 0;
#else
  return false;
#endif
}

// Safe socket operations with proper error handling
bool ReadExact(int socket_fd, char* buffer, std::size_t size) {
    if (!buffer || size == 0) {
        return false;
    }
    
    std::size_t total_read = 0;
    int retry_count = 0;

    while (total_read < size) {
        ssize_t bytes_read = recv(socket_fd, buffer + total_read, size - total_read, 0);

        if (bytes_read > 0) {
            total_read += static_cast<std::size_t>(bytes_read);
            retry_count = 0;
        } else if (bytes_read == 0) {
            // Connection closed
            return false;
        } else {
            // Error occurred
            if (errno == EINTR) {
                if (++retry_count > MAX_RETRIES) {
                    return false;
                }
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++retry_count > MAX_RETRIES) {
                    return false;
                }
                continue;
            } else {
                // Other errors
                return false;
            }
        }
    }

    return true;
}

bool ReadHttpRequest(int socket_fd, std::string& out_raw_request) {
    std::string request;
    request.reserve(READ_BUFFER_SIZE);

    char buffer[READ_BUFFER_SIZE];
    bool headers_parsed = false;
    std::size_t content_length = 0;
    std::size_t header_end_index = std::string::npos;
    int retry_count = 0;

    while (true) {
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer), 0);

        if (bytes_read > 0) {
            request.append(buffer, static_cast<std::size_t>(bytes_read));
            retry_count = 0;
        } else if (bytes_read == 0) {
            return false; // Connection closed
        } else {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++retry_count > MAX_RETRIES) {
                    return false;
                }
                continue;
            }
            return false;
        }

        if (!headers_parsed) {
            std::size_t pos = request.find("\r\n\r\n");
            if (pos != std::string::npos) {
                header_end_index = pos + 4;

                std::string header_part = request.substr(0, header_end_index);

                std::size_t line_end = header_part.find("\r\n");
                if (line_end == std::string::npos) {
                    return false;
                }

                std::size_t headers_start = line_end + 2;

                while (headers_start < header_part.size()) {
                    std::size_t next_end = header_part.find("\r\n", headers_start);
                    if (next_end == std::string::npos || next_end == headers_start) {
                        break;
                    }

                    std::string header_line = 
                        header_part.substr(headers_start, next_end - headers_start);
                    headers_start = next_end + 2;

                    std::size_t colon_pos = header_line.find(':');
                    if (colon_pos == std::string::npos) {
                        continue;
                    }

                    std::string name = ToLower(header_line.substr(0, colon_pos));
                    std::string value = header_line.substr(colon_pos + 1);

                    // Trim whitespace
                    std::size_t first_not_space = value.find_first_not_of(" \t");
                    if (first_not_space != std::string::npos) {
                        value = value.substr(first_not_space);
                        std::size_t last_not_space = value.find_last_not_of(" \t");
                        if (last_not_space != std::string::npos) {
                            value = value.substr(0, last_not_space + 1);
                        }
                    } else {
                        value.clear();
                    }

                    if (name == "content-length") {
                        char* end_ptr = nullptr;
                        unsigned long parsed_length = std::strtoul(value.c_str(), &end_ptr, 10);
                        
                        if (end_ptr != value.c_str() && *end_ptr == '\0') {
                            content_length = static_cast<std::size_t>(parsed_length);
                        } else {
                            return false; // Invalid content-length
                        }
                    }
                }

                headers_parsed = true;

                // DOS protection
                if (content_length > MAX_REQUEST_SIZE) {
                    return false;
                }
            }
        }

        if (headers_parsed) {
            std::size_t body_size = request.size() - header_end_index;
            if (body_size >= content_length) {
                break;
            }
        }

        // DOS protection - check total size
        if (request.size() > MAX_REQUEST_SIZE) {
            return false;
        }
    }

    out_raw_request = std::move(request);
    return true;
}

bool ParseHttpRequest(const std::string& raw_request, HttpRequest& out_request) {
    std::size_t header_end_index = raw_request.find("\r\n\r\n");
    if (header_end_index == std::string::npos) {
        return false;
    }

    std::string header_part = raw_request.substr(0, header_end_index + 2);
    std::string body_part = raw_request.substr(header_end_index + 4);

    std::size_t line_end = header_part.find("\r\n");
    if (line_end == std::string::npos) {
        return false;
    }

    std::string request_line = header_part.substr(0, line_end);

    // Parse request line more safely
    std::istringstream line_stream(request_line);
    if (!(line_stream >> out_request.Method >> out_request.Path >> out_request.Version)) {
        return false;
    }

    // Security: Validate method
    if (out_request.Method != "GET" && out_request.Method != "POST" && 
        out_request.Method != "HEAD" && out_request.Method != "OPTIONS") {
        return false;
    }

    // Security: Validate path length and characters
    if (out_request.Path.empty() || out_request.Path.size() > 2048) {
        return false;
    }

    // Remove query string
    std::size_t query_pos = out_request.Path.find('?');
    if (query_pos != std::string::npos) {
        out_request.Path = out_request.Path.substr(0, query_pos);
    }

    // Security: Basic path traversal protection
    if (out_request.Path.find("..") != std::string::npos) {
        return false;
    }

    // Parse headers
    std::size_t headers_start = line_end + 2;
    while (headers_start < header_part.size()) {
        std::size_t next_end = header_part.find("\r\n", headers_start);
        if (next_end == std::string::npos || next_end == headers_start) {
            break;
        }

        std::string header_line = 
            header_part.substr(headers_start, next_end - headers_start);
        headers_start = next_end + 2;

        std::size_t colon_pos = header_line.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        std::string name = header_line.substr(0, colon_pos);
        std::string value = header_line.substr(colon_pos + 1);

        // Trim whitespace properly
        std::size_t first_not_space = value.find_first_not_of(" \t");
        if (first_not_space != std::string::npos) {
            value = value.substr(first_not_space);
            std::size_t last_not_space = value.find_last_not_of(" \t");
            if (last_not_space != std::string::npos) {
                value = value.substr(0, last_not_space + 1);
            }
        } else {
            value.clear();
        }

        // Limit header count for DOS protection
        if (out_request.Headers.size() >= 50) {
            return false;
        }

        out_request.Headers[ToLower(name)] = std::move(value);
    }

    out_request.Body = std::move(body_part);
    return true;
}

std::string GetHeader(const HttpRequest &Request, const std::string &Name) {
  auto Iterator = Request.Headers.find(ToLower(Name));
  if (Iterator != Request.Headers.end()) {
    return Iterator->second;
  }
  return std::string();
}

bool SendRaw(int socket_fd, const std::string& data) {
    std::size_t total_sent = 0;
    int retry_count = 0;

    while (total_sent < data.size()) {
        ssize_t sent = send(socket_fd, data.data() + total_sent, 
                           data.size() - total_sent, MSG_NOSIGNAL);
        
        if (sent > 0) {
            total_sent += static_cast<std::size_t>(sent);
            retry_count = 0;
        } else if (sent == 0) {
            return false; // Connection closed
        } else {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++retry_count > MAX_RETRIES) {
                    return false;
                }
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
                return false; // Connection broken
            } else {
                return false; // Other errors
            }
        }
    }
    
    return true;
}

bool SendResponse(int socket_fd, int status_code, const std::string& status_text,
                  const std::string& body, 
                  const std::string& content_type = "text/plain; charset=utf-8") {
    std::ostringstream response_stream;
    response_stream << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
    response_stream << "Content-Type: " << content_type << "\r\n";
    response_stream << "Content-Length: " << body.size() << "\r\n";
    response_stream << "Connection: close\r\n";
    response_stream << "Server: megra-police/1.0\r\n";
    response_stream << "X-Content-Type-Options: nosniff\r\n";
    response_stream << "\r\n";
    response_stream << body;

    std::string response = response_stream.str();
    return SendRaw(socket_fd, response);
}

std::string GetCurrentTimeString() {
  std::time_t Now = std::time(nullptr);
  std::tm *TimeInfo = std::localtime(&Now);

  char Buffer[64] = {0};
  if (TimeInfo != nullptr) {
    std::strftime(Buffer, sizeof(Buffer), "%Y-%m-%d %H:%M:%S", TimeInfo);
  }

  return std::string(Buffer);
}

void AddLogEntry(std::vector<std::string> &Logs, const std::string &ClientIp,
                 const HttpRequest &Request, int StatusCode) {
  std::ostringstream EntryStream;
  EntryStream << GetCurrentTimeString() << " ";
  EntryStream << ClientIp << " ";
  EntryStream << Request.Method << " " << Request.Path << " ";
  EntryStream << StatusCode;

  Logs.push_back(EntryStream.str());
}

bool HandleFileUpload(const HttpRequest &Request, std::string &OutMessage) {
  std::string ContentType = GetHeader(Request, "Content-Type");
  if (ContentType.empty()) {
    OutMessage = "Content-Type header is missing.\n";
    return false;
  }

  std::string LowerContentType = ToLower(ContentType);
  if (LowerContentType.find("multipart/form-data") == std::string::npos) {
    OutMessage = "Unsupported Content-Type. Expected multipart/form-data.\n";
    return false;
  }

  std::size_t BoundaryPosLower = LowerContentType.find("boundary=");
  if (BoundaryPosLower == std::string::npos) {
    OutMessage = "Boundary parameter is missing in Content-Type header.\n";
    return false;
  }

  std::size_t BoundaryValueStart = BoundaryPosLower + 9;
  if (BoundaryValueStart >= ContentType.size()) {
    OutMessage = "Boundary value is empty.\n";
    return false;
  }

  std::string Boundary = ContentType.substr(BoundaryValueStart);

  std::size_t FirstNotSpace = Boundary.find_first_not_of(" \t");
  if (FirstNotSpace != std::string::npos) {
    Boundary = Boundary.substr(FirstNotSpace);
  }

  if (!Boundary.empty() && Boundary[0] == '"') {
    std::size_t QuoteEnd = Boundary.find('"', 1);
    if (QuoteEnd == std::string::npos || QuoteEnd <= 1) {
      OutMessage = "Boundary value is malformed.\n";
      return false;
    }
    Boundary = Boundary.substr(1, QuoteEnd - 1);
  } else {
    std::size_t SemicolonPos = Boundary.find(';');
    if (SemicolonPos != std::string::npos) {
      Boundary = Boundary.substr(0, SemicolonPos);
    }
  }

  std::size_t LastNotSpace = Boundary.find_last_not_of(" \t");
  if (LastNotSpace != std::string::npos) {
    Boundary = Boundary.substr(0, LastNotSpace + 1);
  }

  if (Boundary.empty()) {
    OutMessage = "Boundary value is empty.\n";
    return false;
  }

  std::string BoundaryMarker = "--" + Boundary;

  const std::string &Body = Request.Body;

  std::size_t FirstBoundaryPos = Body.find(BoundaryMarker);
  if (FirstBoundaryPos == std::string::npos) {
    OutMessage = "Boundary not found in request body.\n";
    return false;
  }

  std::size_t PartHeadersStart = Body.find("\r\n", FirstBoundaryPos);
  if (PartHeadersStart == std::string::npos) {
    OutMessage = "Malformed multipart data (no CRLF after boundary).\n";
    return false;
  }

  PartHeadersStart += 2;

  std::size_t PartHeadersEnd = Body.find("\r\n\r\n", PartHeadersStart);
  if (PartHeadersEnd == std::string::npos) {
    OutMessage = "Malformed multipart data (no header terminator).\n";
    return false;
  }

  std::string PartHeaders =
      Body.substr(PartHeadersStart, PartHeadersEnd - PartHeadersStart);

  std::istringstream HeadersStream(PartHeaders);
  std::string Line;
  std::string FileName;

  while (std::getline(HeadersStream, Line)) {
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();
    }

    std::size_t ColonPos = Line.find(':');
    if (ColonPos == std::string::npos) {
      continue;
    }

    std::string Name = ToLower(Line.substr(0, ColonPos));
    std::string Value = Line.substr(ColonPos + 1);

    std::size_t FirstNotSpace = Value.find_first_not_of(" \t");
    if (FirstNotSpace != std::string::npos) {
      Value = Value.substr(FirstNotSpace);
    }

    if (Name == "content-disposition") {
      std::string LowerValue = ToLower(Value);
      if (LowerValue.find("form-data") == std::string::npos) {
        continue;
      }

      std::size_t FilenamePos = LowerValue.find("filename=");
      if (FilenamePos != std::string::npos) {
        std::size_t QuoteStart = Value.find('"', FilenamePos);
        if (QuoteStart != std::string::npos) {
          std::size_t QuoteEnd = Value.find('"', QuoteStart + 1);
          if (QuoteEnd != std::string::npos && QuoteEnd > QuoteStart + 1) {
            FileName = Value.substr(QuoteStart + 1, QuoteEnd - QuoteStart - 1);
          }
        }
      }
    }
  }

  if (FileName.empty()) {
    OutMessage = "Filename not found in Content-Disposition.\n";
    return false;
  }

  // Security: Remove path components and validate filename
  std::size_t slash_pos = FileName.find_last_of("/\\");
  if (slash_pos != std::string::npos) {
    FileName = FileName.substr(slash_pos + 1);
  }

  if (FileName.empty()) {
    FileName = "upload.bin";
  }

  // Security: Validate filename
  if (!IsValidFileName(FileName)) {
    OutMessage = "Invalid filename.\n";
    return false;
  }

  std::size_t FileDataStart = PartHeadersEnd + 4;
  if (FileDataStart >= Body.size()) {
    OutMessage = "No file data found in request body.\n";
    return false;
  }

  std::size_t FileDataEnd = Body.find(BoundaryMarker, FileDataStart);
  if (FileDataEnd == std::string::npos) {
    OutMessage = "Closing boundary not found after file data.\n";
    return false;
  }

  if (FileDataEnd >= 2 && Body.substr(FileDataEnd - 2, 2) == "\r\n") {
    FileDataEnd -= 2;
  }

  if (FileDataEnd <= FileDataStart) {
    OutMessage = "Empty file data.\n";
    return false;
  }

  std::size_t FileSize = FileDataEnd - FileDataStart;

  std::string full_path = "/tmp/" + FileName;

  // Security: Check file size limits
  if (FileSize > 10 * 1024 * 1024) { // 10MB limit
    OutMessage = "File too large (max 10MB).\n";
    return false;
  }

  std::ofstream output(full_path, std::ios::binary | std::ios::trunc);
  if (!output) {
    OutMessage = "Failed to open output file.\n";
    return false;
  }

  output.write(Body.data() + FileDataStart, static_cast<std::streamsize>(FileSize));
  if (!output.good()) {
    OutMessage = "Failed to write file data.\n";
    output.close();
    // Try to remove partially written file
    std::remove(full_path.c_str());
    return false;
  }

  output.close();
  if (!output.good()) {
    OutMessage = "Failed to close file properly.\n";
    std::remove(full_path.c_str());
    return false;
  }

  std::ostringstream message_stream;
  message_stream << "File uploaded successfully to " << full_path << "\n";
  OutMessage = message_stream.str();
  return true;
}

void HandleClient(Socket& client_socket, std::vector<std::string>& logs,
                  const std::string& client_ip) {
    std::string raw_request;
    if (!ReadHttpRequest(client_socket.get(), raw_request)) {
        SendResponse(client_socket.get(), 400, "Bad Request",
                     "Failed to read HTTP request.\n");
        return;
    }

    HttpRequest request;
    if (!ParseHttpRequest(raw_request, request)) {
        SendResponse(client_socket.get(), 400, "Bad Request", 
                     "Malformed HTTP request.\n");
        return;
    }

    int status_code = 500;
    std::string status_text = "Internal Server Error";
    std::string response_body = "Internal Server Error\n";
    std::string content_type = "text/plain; charset=utf-8";

    if (request.Path == "/info" && request.Method == "GET") {
        status_code = 200;
        status_text = "OK";
        response_body = "Все ок\n";
    } else if (request.Path == "/log" && request.Method == "GET") {
        std::ostringstream body_stream;
        for (const std::string& entry : logs) {
            body_stream << entry << "\n";
        }

        status_code = 200;
        status_text = "OK";
        response_body = body_stream.str();
    } else if (request.Path == "/upload" && request.Method == "POST") {
        std::string message;
        bool success = HandleFileUpload(request, message);

        if (success) {
            status_code = 200;
            status_text = "OK";
            response_body = std::move(message);
        } else {
            status_code = 400;
            status_text = "Bad Request";
            response_body = std::move(message);
        }
    } else {
        status_code = 404;
        status_text = "Not Found";
        response_body = "Not Found\n";
    }

    AddLogEntry(logs, client_ip, request, status_code);
    SendResponse(client_socket.get(), status_code, status_text, response_body, content_type);
}

int main() {
    // Ignore SIGPIPE to prevent crashes on broken connections
    signal(SIGPIPE, SIG_IGN);
    
    if (!IsRunningAsRoot()) {
        std::cerr << "Эта программа должна быть запущена от root.\n";
        return 1;
    }

    Socket server_socket(socket(AF_INET, SOCK_STREAM, 0));
    if (!server_socket.is_valid()) {
        std::cerr << "Не удалось создать сокет: " << std::strerror(errno) << "\n";
        return 1;
    }

    // Set socket options
    int option_value = 1;
    if (setsockopt(server_socket.get(), SOL_SOCKET, SO_REUSEADDR, 
                   &option_value, sizeof(option_value)) < 0) {
        std::cerr << "Не удалось установить SO_REUSEADDR: " << std::strerror(errno) << "\n";
        return 1;
    }

    // Additional socket options for robustness
    if (setsockopt(server_socket.get(), SOL_SOCKET, SO_REUSEPORT,
                   &option_value, sizeof(option_value)) < 0) {
        // SO_REUSEPORT might not be available on all systems, ignore error
    }

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(SERVER_PORT);

    if (bind(server_socket.get(), reinterpret_cast<sockaddr*>(&server_address),
             sizeof(server_address)) < 0) {
        std::cerr << "Не удалось выполнить bind на порт " << SERVER_PORT 
                  << ": " << std::strerror(errno) << "\n";
        return 1;
    }

    if (listen(server_socket.get(), LISTEN_BACKLOG) < 0) {
        std::cerr << "Не удалось перевести сокет в состояние прослушивания: " 
                  << std::strerror(errno) << "\n";
        return 1;
    }

    std::cout << "HTTP сервер запущен на порту " << SERVER_PORT << ".\n";

    std::vector<std::string> logs;
    logs.reserve(1000); // Предварительное выделение памяти

    while (true) {
        sockaddr_in client_address{};
        socklen_t client_address_length = sizeof(client_address);

        int client_fd = accept(server_socket.get(), 
                              reinterpret_cast<sockaddr*>(&client_address),
                              &client_address_length);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal, try again
            }
            std::cerr << "Ошибка accept(): " << std::strerror(errno) << "\n";
            continue;
        }

        Socket client_socket(client_fd);

        char address_buffer[INET_ADDRSTRLEN] = {};
        const char* address_string = inet_ntop(AF_INET, &client_address.sin_addr,
                                              address_buffer, sizeof(address_buffer));
        std::string client_ip = address_string ? std::string(address_string) : 
                                               std::string("unknown");

        HandleClient(client_socket, logs, client_ip);
        // client_socket automatically closes when going out of scope
    }

    // server_socket automatically closes when going out of scope
    return 0;
}

#else

#include <iostream>

int main() {
  std::cerr << "This program is intended to run on Linux (armhf).\n";
  return 1;
}

#endif
