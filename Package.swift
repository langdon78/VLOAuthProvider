// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VLOAuthProvider",
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v6)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "VLOAuthProvider",
            targets: ["VLOAuthProvider"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections.git", .upToNextMajor(from: "1.2.1")),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "VLOAuthProvider",
            dependencies: [
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]),
        .testTarget(
            name: "VLOAuthProviderTests",
            dependencies: ["VLOAuthProvider"]),
    ]
)
