// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "http_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "log.h"

namespace prism {

namespace {

// Consume the whole request head (through the blank line). Leaving bytes
// unread would make close() emit RST and drop our unsent response body.
// Returns just the request line, e.g. "GET /metrics HTTP/1.1".
std::string readRequest(int fd) {
    std::string head;
    char buf[1024];
    while (head.size() < 16384) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        head.append(buf, static_cast<size_t>(n));
        if (head.find("\r\n\r\n") != std::string::npos ||
            head.find("\n\n") != std::string::npos) {
            break;
        }
    }
    size_t eol = head.find('\n');
    std::string line = (eol == std::string::npos) ? head : head.substr(0, eol);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

void sendAll(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::send(fd, s.data() + off, s.size() - off, 0);
        if (n <= 0) break;
        off += static_cast<size_t>(n);
    }
}

void respond(int fd, int code, const char* status, const std::string& ctype,
             const std::string& body) {
    std::string h = "HTTP/1.1 " + std::to_string(code) + " " + status + "\r\n";
    h += "Content-Type: " + ctype + "\r\n";
    h += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    h += "Connection: close\r\n\r\n";
    sendAll(fd, h);
    sendAll(fd, body);
}

}  // namespace

MetricsServer::MetricsServer(std::string bind_addr, uint16_t port,
                             std::function<std::string()> render)
    : addr_(std::move(bind_addr)), port_(port), render_(std::move(render)) {}

MetricsServer::~MetricsServer() { stop(); }

bool MetricsServer::start(std::string& err) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port_);
    if (::inet_pton(AF_INET, addr_.c_str(), &sa.sin_addr) != 1) {
        err = "bad metrics bind address: " + addr_;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0 ||
        ::listen(listen_fd_, 16) < 0) {
        err = std::string("bind/listen ") + addr_ + ":" + std::to_string(port_) + ": " +
              std::strerror(errno);
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    // Report the actual port (useful when port 0 was requested).
    socklen_t sl = sizeof(sa);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&sa), &sl) == 0)
        port_ = ntohs(sa.sin_port);

    running_ = true;
    thread_ = std::thread(&MetricsServer::loop, this);
    PLOG_INFO("metrics") << "serving /metrics on " << addr_ << ":" << port_;
    return true;
}

void MetricsServer::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (thread_.joinable()) thread_.join();
}

void MetricsServer::loop() {
    while (running_) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (!running_) break;
            if (errno == EINTR) continue;
            break;
        }
        const std::string req = readRequest(fd);  // e.g. "GET /metrics HTTP/1.1"

        std::string method, path;
        {
            size_t s1 = req.find(' ');
            size_t s2 = (s1 == std::string::npos) ? std::string::npos : req.find(' ', s1 + 1);
            if (s1 != std::string::npos) {
                method = req.substr(0, s1);
                path = req.substr(s1 + 1, (s2 == std::string::npos ? req.size() : s2) - s1 - 1);
            }
        }

        if (method == "GET" && (path == "/metrics" || path == "/metrics/")) {
            respond(fd, 200, "OK", "text/plain; version=0.0.4", render_ ? render_() : "");
        } else if (method == "GET" && (path == "/healthz" || path == "/")) {
            respond(fd, 200, "OK", "text/plain", "ok\n");
        } else {
            respond(fd, 404, "Not Found", "text/plain", "not found\n");
        }
        // Graceful close: FIN + flush, then drain anything still inbound so the
        // kernel doesn't RST (which would truncate the body just written).
        ::shutdown(fd, SHUT_WR);
        char sink[512];
        while (::recv(fd, sink, sizeof(sink), MSG_DONTWAIT) > 0) {
        }
        ::close(fd);
    }
}

}  // namespace prism
