
#include "tls_client.hpp"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    // Default: api.binance.com at 443 with explicit host header and SNI.
    std::string host = argc > 1 ? argv[1] : "api.binance.com";
    std::string port = argc > 2 ? argv[2] : "443";
    std::string host_header = argc > 3 ? argv[3] : host; // override Host header if connecting by IP

    try {
        TLSClient client;
        client.set_min_max_tls12();
        // Prefer legacy RSA/AES128/CBC/SHA1; allow fallback if server rejects this suite.
        client.set_cipher_list("TLS_RSA_WITH_AES_128_CBC_SHA:RSA+AES128+SHA:!aNULL:!eNULL");

        client.set_sni(host_header);
        client.connect(host, port);

        std::string req =
            "GET /api/v3/time HTTP/1.1\r\n"
            "Host: " + host_header + "\r\n"
            "User-Agent: tls12_rsa_aes128cbc_sha_demo/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n";

        client.write(req);
        std::string resp = client.read_all();
        std::cout << resp << std::endl;

        client.shutdown();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
