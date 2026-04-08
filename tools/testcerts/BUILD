load("//bazel:envoy_build_system.bzl", "envoy_package")

licenses(["notice"])  # Apache 2

envoy_package()

cc_binary(
    name = "generate_test_certs",
    srcs = ["generate_test_certs.cc"],
    deps = [
        "//bazel:crypto",
        "//bazel:ssl",
    ],
)
