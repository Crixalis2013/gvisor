load("//tools:defs.bzl", "go_test")

package(licenses = ["notice"])

go_test(
    name = "ip_test",
    size = "small",
    srcs = [
        "ip_test.go",
    ],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
    ],
)
