
#pragma once
#include <string>

class TLSClient {
public:
    TLSClient();
    ~TLSClient();

    // Disallow copy
    TLSClient(const TLSClient&) = delete;
    TLSClient& operator=(const TLSClient&) = delete;

    void set_min_max_tls12();
    void set_cipher_list(const std::string& cipher_list);
    void set_sni(const std::string& sni_hostname);

    // host can be DNS name or IP; port string like "443"
    void connect(const std::string& host, const std::string& port);

    void write(const std::string& data);
    std::string read_all();
    void shutdown();

private:
    struct Impl;
    Impl* impl;
};
