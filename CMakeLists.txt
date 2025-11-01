
cmake_minimum_required(VERSION 3.10)
project(tls12_rsa_aes128cbc_sha_demo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(tls12_rsa_aes128cbc_sha
    src/main.cpp
    src/tls_client.cpp
)

target_include_directories(tls12_rsa_aes128cbc_sha PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(tls12_rsa_aes128cbc_sha PRIVATE OpenSSL::SSL OpenSSL::Crypto)
