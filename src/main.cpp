#ifdef __linux__

#include <arpa/inet.h>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {
const int SERVER_PORT = 1616;
const std::size_t MAX_REQUEST_SIZE = 50 * 1024 * 1024; // 50 MB
const int LISTEN_BACKLOG = 10;
} // anonymous namespace

struct HttpRequest {
  std::string Method;
  std::string Path;
  std::string Version;
  std::map<std::string, std::string> Headers;
  std::string Body;
};

std::string ToLower(const std::string &Text) {
  std::string Result = Text;
  for (char &Character : Result) {
    if (Character >= 'A' && Character <= 'Z') {
      Character = static_cast<char>(Character - 'A' + 'a');
    }
  }
  return Result;
}

bool IsRunningAsRoot() {
#ifdef __linux__
  uid_t UserId = getuid();
  return UserId == 0;
#else
  return false;
#endif
}

bool ReadExact(int Socket, char *Buffer, std::size_t Size) {
  std::size_t TotalRead = 0;

  while (TotalRead < Size) {
    ssize_t BytesRead = recv(Socket, Buffer + TotalRead, Size - TotalRead, 0);

    if (BytesRead <= 0) {
      return false;
    }

    TotalRead += static_cast<std::size_t>(BytesRead);
  }

  return true;
}

bool ReadHttpRequest(int Socket, std::string &OutRawRequest) {
  std::string Request;
  Request.reserve(4096);

  char Buffer[4096];
  bool HeadersParsed = false;
  std::size_t ContentLength = 0;
  std::size_t HeaderEndIndex = std::string::npos;

  while (true) {
    ssize_t BytesRead = recv(Socket, Buffer, sizeof(Buffer), 0);

    if (BytesRead <= 0) {
      return false;
    }

    Request.append(Buffer, static_cast<std::size_t>(BytesRead));

    if (!HeadersParsed) {
      std::size_t Pos = Request.find("\r\n\r\n");
      if (Pos != std::string::npos) {
        HeaderEndIndex = Pos + 4;

        std::string HeaderPart = Request.substr(0, HeaderEndIndex);

        std::size_t LineEnd = HeaderPart.find("\r\n");
        if (LineEnd == std::string::npos) {
          return false;
        }

        std::size_t HeadersStart = LineEnd + 2;

        while (HeadersStart < HeaderPart.size()) {
          std::size_t NextEnd = HeaderPart.find("\r\n", HeadersStart);
          if (NextEnd == std::string::npos || NextEnd == HeadersStart) {
            break;
          }

          std::string HeaderLine =
              HeaderPart.substr(HeadersStart, NextEnd - HeadersStart);
          HeadersStart = NextEnd + 2;

          std::size_t ColonPos = HeaderLine.find(':');
          if (ColonPos == std::string::npos) {
            continue;
          }

          std::string Name = ToLower(HeaderLine.substr(0, ColonPos));
          std::string Value = HeaderLine.substr(ColonPos + 1);

          std::size_t FirstNotSpace = Value.find_first_not_of(" \t");
          if (FirstNotSpace != std::string::npos) {
            Value = Value.substr(FirstNotSpace);
          }

          if (Name == "content-length") {
            ContentLength = static_cast<std::size_t>(
                std::strtoul(Value.c_str(), nullptr, 10));
          }
        }

        HeadersParsed = true;

        if (ContentLength > MAX_REQUEST_SIZE) {
          return false;
        }
      }
    }

    if (HeadersParsed) {
      std::size_t BodySize = Request.size() - HeaderEndIndex;
      if (BodySize >= ContentLength) {
        break;
      }
    }

    if (Request.size() > MAX_REQUEST_SIZE) {
      return false;
    }
  }

  OutRawRequest.swap(Request);
  return true;
}

bool ParseHttpRequest(const std::string &RawRequest, HttpRequest &OutRequest) {
  std::size_t HeaderEndIndex = RawRequest.find("\r\n\r\n");
  if (HeaderEndIndex == std::string::npos) {
    return false;
  }

  std::string HeaderPart = RawRequest.substr(0, HeaderEndIndex + 2);
  std::string BodyPart = RawRequest.substr(HeaderEndIndex + 4);

  std::size_t LineEnd = HeaderPart.find("\r\n");
  if (LineEnd == std::string::npos) {
    return false;
  }

  std::string RequestLine = HeaderPart.substr(0, LineEnd);

  std::istringstream LineStream(RequestLine);
  if (!(LineStream >> OutRequest.Method >> OutRequest.Path >>
        OutRequest.Version)) {
    return false;
  }

  std::size_t QueryPos = OutRequest.Path.find('?');
  if (QueryPos != std::string::npos) {
    OutRequest.Path = OutRequest.Path.substr(0, QueryPos);
  }

  std::size_t HeadersStart = LineEnd + 2;
  while (HeadersStart < HeaderPart.size()) {
    std::size_t NextEnd = HeaderPart.find("\r\n", HeadersStart);
    if (NextEnd == std::string::npos || NextEnd == HeadersStart) {
      break;
    }

    std::string HeaderLine =
        HeaderPart.substr(HeadersStart, NextEnd - HeadersStart);
    HeadersStart = NextEnd + 2;

    std::size_t ColonPos = HeaderLine.find(':');
    if (ColonPos == std::string::npos) {
      continue;
    }

    std::string Name = HeaderLine.substr(0, ColonPos);
    std::string Value = HeaderLine.substr(ColonPos + 1);

    std::size_t FirstNotSpace = Value.find_first_not_of(" \t");
    if (FirstNotSpace != std::string::npos) {
      Value = Value.substr(FirstNotSpace);
    }

    OutRequest.Headers[ToLower(Name)] = Value;
  }

  OutRequest.Body = BodyPart;
  return true;
}

std::string GetHeader(const HttpRequest &Request, const std::string &Name) {
  auto Iterator = Request.Headers.find(ToLower(Name));
  if (Iterator != Request.Headers.end()) {
    return Iterator->second;
  }
  return std::string();
}

void SendRaw(int Socket, const std::string &Data) {
  std::size_t TotalSent = 0;

  while (TotalSent < Data.size()) {
    ssize_t Sent =
        send(Socket, Data.data() + TotalSent, Data.size() - TotalSent, 0);
    if (Sent <= 0) {
      break;
    }
    TotalSent += static_cast<std::size_t>(Sent);
  }
}

void SendResponse(
    int Socket, int StatusCode, const std::string &StatusText,
    const std::string &Body,
    const std::string &ContentType = "text/plain; charset=utf-8") {
  std::ostringstream ResponseStream;
  ResponseStream << "HTTP/1.1 " << StatusCode << " " << StatusText << "\r\n";
  ResponseStream << "Content-Type: " << ContentType << "\r\n";
  ResponseStream << "Content-Length: " << Body.size() << "\r\n";
  ResponseStream << "Connection: close\r\n";
  ResponseStream << "\r\n";
  ResponseStream << Body;

  std::string Response = ResponseStream.str();
  SendRaw(Socket, Response);
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

  std::size_t BoundaryPos = LowerContentType.find("boundary=");
  if (BoundaryPos == std::string::npos) {
    OutMessage = "Boundary parameter is missing in Content-Type header.\n";
    return false;
  }

  std::string Boundary = LowerContentType.substr(BoundaryPos + 9);
  if (!Boundary.empty() && Boundary[0] == '"') {
    std::size_t QuoteEnd = Boundary.find('"', 1);
    Boundary = Boundary.substr(1, QuoteEnd - 1);
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

  std::size_t SlashPos = FileName.find_last_of("/\\");
  if (SlashPos != std::string::npos) {
    FileName = FileName.substr(SlashPos + 1);
  }

  if (FileName.empty()) {
    FileName = "upload.bin";
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

  std::string FullPath = "/tmp/" + FileName;

  std::ofstream Output(FullPath.c_str(), std::ios::binary);
  if (!Output) {
    OutMessage = "Failed to open output file.\n";
    return false;
  }

  Output.write(Body.data() + FileDataStart,
               static_cast<std::streamsize>(FileSize));
  if (!Output) {
    OutMessage = "Failed to write all file data.\n";
    return false;
  }

  Output.close();

  std::ostringstream MessageStream;
  MessageStream << "File uploaded successfully to " << FullPath << "\n";
  OutMessage = MessageStream.str();
  return true;
}

void HandleClient(int ClientSocket, std::vector<std::string> &Logs,
                  const std::string &ClientIp) {
  std::string RawRequest;
  if (!ReadHttpRequest(ClientSocket, RawRequest)) {
    SendResponse(ClientSocket, 400, "Bad Request",
                 "Failed to read HTTP request.\n");
    return;
  }

  HttpRequest Request;
  if (!ParseHttpRequest(RawRequest, Request)) {
    SendResponse(ClientSocket, 400, "Bad Request", "Malformed HTTP request.\n");
    return;
  }

  int StatusCode = 500;
  std::string StatusText = "Internal Server Error";
  std::string ResponseBody = "Internal Server Error\n";
  std::string ContentType = "text/plain; charset=utf-8";

  if (Request.Path == "/info" && Request.Method == "GET") {
    StatusCode = 200;
    StatusText = "OK";
    ResponseBody = "Все ок\n";
  } else if (Request.Path == "/log" && Request.Method == "GET") {
    std::ostringstream BodyStream;
    for (const std::string &Entry : Logs) {
      BodyStream << Entry << "\n";
    }

    StatusCode = 200;
    StatusText = "OK";
    ResponseBody = BodyStream.str();
  } else if (Request.Path == "/upload" && Request.Method == "POST") {
    std::string Message;
    bool Success = HandleFileUpload(Request, Message);

    if (Success) {
      StatusCode = 200;
      StatusText = "OK";
      ResponseBody = Message;
    } else {
      StatusCode = 400;
      StatusText = "Bad Request";
      ResponseBody = Message;
    }
  } else {
    StatusCode = 404;
    StatusText = "Not Found";
    ResponseBody = "Not Found\n";
  }

  AddLogEntry(Logs, ClientIp, Request, StatusCode);
  SendResponse(ClientSocket, StatusCode, StatusText, ResponseBody, ContentType);
}

int main() {
  if (!IsRunningAsRoot()) {
    std::cerr << "Эта программа должна быть запущена от root.\n";
    return 1;
  }

  int ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (ServerSocket < 0) {
    std::cerr << "Не удалось создать сокет.\n";
    return 1;
  }

  int OptionValue = 1;
  if (setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, &OptionValue,
                 sizeof(OptionValue)) < 0) {
    std::cerr << "Не удалось установить опцию SO_REUSEADDR.\n";
    close(ServerSocket);
    return 1;
  }

  sockaddr_in ServerAddress;
  ServerAddress.sin_family = AF_INET;
  ServerAddress.sin_addr.s_addr = htonl(INADDR_ANY);
  ServerAddress.sin_port = htons(SERVER_PORT);

  if (bind(ServerSocket, reinterpret_cast<sockaddr *>(&ServerAddress),
           sizeof(ServerAddress)) < 0) {
    std::cerr << "Не удалось выполнить bind на порт " << SERVER_PORT << ".\n";
    close(ServerSocket);
    return 1;
  }

  if (listen(ServerSocket, LISTEN_BACKLOG) < 0) {
    std::cerr << "Не удалось перевести сокет в состояние прослушивания.\n";
    close(ServerSocket);
    return 1;
  }

  std::cout << "HTTP сервер запущен на порту " << SERVER_PORT << ".\n";

  std::vector<std::string> Logs;

  while (true) {
    sockaddr_in ClientAddress;
    socklen_t ClientAddressLength = sizeof(ClientAddress);

    int ClientSocket =
        accept(ServerSocket, reinterpret_cast<sockaddr *>(&ClientAddress),
               &ClientAddressLength);
    if (ClientSocket < 0) {
      std::cerr << "Ошибка accept().\n";
      continue;
    }

    char AddressBuffer[INET_ADDRSTRLEN] = {0};
    const char *AddressString = inet_ntop(AF_INET, &ClientAddress.sin_addr,
                                          AddressBuffer, sizeof(AddressBuffer));
    std::string ClientIp =
        AddressString ? std::string(AddressString) : std::string("unknown");

    HandleClient(ClientSocket, Logs, ClientIp);

    close(ClientSocket);
  }

  close(ServerSocket);
  return 0;
}

#else

#include <iostream>

int main() {
  std::cerr << "This program is intended to run on Linux (armhf).\n";
  return 1;
}

#endif
