// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// A deliberately tiny blocking HTTP/1.1 server for a Prometheus /metrics
// endpoint (and a /healthz). One connection at a time -- Prometheus scrapes
// every ~15s, so throughput is irrelevant. No external HTTP library.

#ifndef PRISM_HTTP_SERVER_H
#define PRISM_HTTP_SERVER_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace prism {

class MetricsServer {
public:
    // `render` is called on every GET /metrics and must be thread-safe.
    MetricsServer(std::string bind_addr, uint16_t port, std::function<std::string()> render);
    ~MetricsServer();

    // Bind + listen + spawn the accept loop. Returns false (and fills err) on
    // a bind failure; the caller decides whether that's fatal.
    bool start(std::string& err);
    void stop();

    uint16_t port() const { return port_; }

private:
    void loop();

    std::string addr_;
    uint16_t port_;
    std::function<std::string()> render_;
    std::atomic<int> listen_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace prism

#endif  // PRISM_HTTP_SERVER_H
