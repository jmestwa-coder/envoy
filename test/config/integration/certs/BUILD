load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

# Generates all standard integration test certificates using BoringSSL APIs.
# No openssl CLI dependency.
# The following intentionally special certs are NOT generated here and remain
# as checked-in static files:
#   - expired_cert.pem / expired_key.pem: intentionally expired; tests reference
#     their specific expiry timestamp (see stats_integration_test.cc).
#   - google_root_certs.pem: real Google root cert for google-grpc tests.
#   - pqc_cacert.pem / pqc_cakey.pem: post-quantum crypto test cert.
genrule(
    name = "generate_certs",
    outs = [
        # Root CA
        "cacert.pem",
        "cakey.pem",
        "cacert_info.h",
        # Intermediate CA
        "intermediate_cacert.pem",
        "intermediate_cakey.pem",
        "intermediate_cacert_info.h",
        # Intermediate CA 2
        "intermediate_ca_2cert.pem",
        "intermediate_ca_2key.pem",
        "intermediate_ca_2cert_info.h",
        # CA chain bundles
        "intermediate_ca_cert_chain.pem",
        "intermediate_partial_ca_cert_chain.pem",
        # Upstream CA
        "upstreamcacert.pem",
        "upstreamcakey.pem",
        "upstreamcacert_info.h",
        # Server certs
        "servercert.pem",
        "serverkey.pem",
        "servercert_info.h",
        "servercert_hash.h",
        "server_ocsp_resp.der",
        "server2cert.pem",
        "server2key.pem",
        "server2cert_info.h",
        "server2cert_hash.h",
        "server_ecdsacert.pem",
        "server_ecdsakey.pem",
        "server_ecdsacert_hash.h",
        "server_ecdsa_ocsp_resp.der",
        "server_ecdsa_p384cert.pem",
        "server_ecdsa_p384key.pem",
        "server_ecdsa_p384cert_hash.h",
        "server_ecdsa_p384_ocsp_resp.der",
        "server_ecdsa_p521cert.pem",
        "server_ecdsa_p521key.pem",
        "server_ecdsa_p521cert_hash.h",
        "server_ecdsa_p521_ocsp_resp.der",
        "long_servercert.pem",
        "long_serverkey.pem",
        "long_servercert_info.h",
        "long_servercert_hash.h",
        "long_server_ocsp_resp.der",
        # Client certs
        "clientcert.pem",
        "clientkey.pem",
        "clientcert_hash.h",
        "client2cert.pem",
        "client2key.pem",
        "client2cert_hash.h",
        "client2_chain.pem",
        "client_ecdsacert.pem",
        "client_ecdsakey.pem",
        "client_ecdsacert_hash.h",
        # Upstream server certs
        "upstreamcert.pem",
        "upstreamkey.pem",
        "upstreamcert_hash.h",
        "upstreamlocalhostcert.pem",
        "upstreamlocalhostkey.pem",
        "upstreamlocalhostcert_hash.h",
    ],
    cmd = "$(location //tools/testcerts:generate_test_certs) $(RULEDIR)",
    tools = ["//tools/testcerts:generate_test_certs"],
)

filegroup(
    name = "certs",
    srcs = [
        ":generate_certs",
        # Static special-purpose certs (intentionally NOT generated):
        "expired_cert.pem",
        "expired_key.pem",
        "google_root_certs.pem",
        "pqc_cacert.pem",
        "pqc_cakey.pem",
    ],
)

envoy_cc_test_library(
    name = "hashes",
    hdrs = [
        ":generate_certs",
        # Static hash headers:
        "expired_cert_hash.h",
        "pqc_cacert_info.h",
    ],
)

envoy_cc_test_library(
    name = "certs_info",
    hdrs = [":generate_certs"],
)

