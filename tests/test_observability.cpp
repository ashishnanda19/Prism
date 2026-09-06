// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Structured logger, Prometheus text helpers, and the /metrics HTTP server
// (exercised over a real loopback socket, in-process).

#include "doctest/doctest.h"

#include "http_server.h"
#include "log.h"
#include "metrics.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <sstream>
#include <string>
#include <thread>

using namespace prism;

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
TEST_CASE("logger honours the level and formats") {
    std::ostringstream sink;
    setLogStream(&sink);
    setLogJson(false);
    setLogLevel(LogLevel::Warn);

    PLOG_INFO("t") << "should be dropped";
    PLOG_WARN("t") << "kept " << 42;
    PLOG_ERROR("net") << "boom";

    const std::string out = sink.str();
    CHECK(out.find("should be dropped") == std::string::npos);
    CHECK(out.find("warn  t: kept 42") != std::string::npos);
    CHECK(out.find("error net: boom") != std::string::npos);

    setLogStream(nullptr);  // restore std::cerr
    setLogLevel(LogLevel::Info);
}

TEST_CASE("logger JSON mode escapes the message") {
    std::ostringstream sink;
    setLogStream(&sink);
    setLogJson(true);
    setLogLevel(LogLevel::Info);

    PLOG_INFO("cli") << "path=\"/tmp/x\"\nsecond line";

    const std::string out = sink.str();
    CHECK(out.rfind("{\"ts\":\"", 0) == 0);
    CHECK(out.find("\"level\":\"info\"") != std::string::npos);
    CHECK(out.find("\"comp\":\"cli\"") != std::string::npos);
    CHECK(out.find("\\\"/tmp/x\\\"\\nsecond line") != std::string::npos);

    setLogJson(false);
    setLogStream(nullptr);
}

TEST_CASE("parseLogLevel") {
    LogLevel l;
    CHECK(parseLogLevel("debug", l));
    CHECK(l == LogLevel::Debug);
    CHECK(parseLogLevel("warning", l));
    CHECK(l == LogLevel::Warn);
    CHECK_FALSE(parseLogLevel("loud", l));
}

// ---------------------------------------------------------------------------
// Prometheus text helpers
// ---------------------------------------------------------------------------
TEST_CASE("metrics text format") {
    const std::string c = metrics::counter("prism_x_total", "an x", 7);
    CHECK(c ==
          "# HELP prism_x_total an x\n"
          "# TYPE prism_x_total counter\n"
          "prism_x_total 7\n");

    const std::string l = metrics::labeled(
        "prism_app_total", "per app", "counter", "app",
        {{"YouTube", 3}, {"Weird \"App\"", 1}});
    CHECK(l.find("prism_app_total{app=\"YouTube\"} 3\n") != std::string::npos);
    CHECK(l.find("prism_app_total{app=\"Weird \\\"App\\\"\"} 1\n") != std::string::npos);
}

// ---------------------------------------------------------------------------
// MetricsServer over loopback
// ---------------------------------------------------------------------------
namespace {
std::string httpGet(uint16_t port, const std::string& path) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);

    const std::string req = "GET " + path + " HTTP/1.0\r\n\r\n";
    ::send(fd, req.data(), req.size(), 0);

    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return resp;
}
}  // namespace

TEST_CASE("MetricsServer serves /metrics, /healthz and 404s") {
    std::atomic<int> hits{0};
    MetricsServer srv("127.0.0.1", 0, [&hits] {
        ++hits;
        return std::string("# HELP prism_up 1\n# TYPE prism_up gauge\nprism_up 1\n");
    });
    std::string err;
    REQUIRE(srv.start(err));
    CHECK(err.empty());
    REQUIRE(srv.port() != 0);

    std::string m = httpGet(srv.port(), "/metrics");
    CHECK(m.find("200 OK") != std::string::npos);
    CHECK(m.find("text/plain; version=0.0.4") != std::string::npos);
    CHECK(m.find("prism_up 1") != std::string::npos);
    CHECK(hits == 1);

    std::string h = httpGet(srv.port(), "/healthz");
    CHECK(h.find("200 OK") != std::string::npos);
    CHECK(h.find("ok") != std::string::npos);

    std::string nf = httpGet(srv.port(), "/nope");
    CHECK(nf.find("404 Not Found") != std::string::npos);

    srv.stop();
}
