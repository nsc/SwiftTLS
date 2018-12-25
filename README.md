# SwiftTLS

SwiftTLS is a Swift-only implementation of TLS 1.3 and 1.2 that hopes to avoid common classes of vulnerabilities that have traditionally plagued C-based implementations like buffer overflows or generally arbitrary memory accesses. It is written entirely in Swift and has no external dependencies, i.e. all public key crypto, symmetric crypto and hash functions are included.

SwiftTLS is licensed under the MIT License.

## Features
Crypto
- RSA-PKCS1 & RSA-PSS, DHE, ECDHE, ECDSA
- CBC and GCM cipher modes
- secp256r1, secp384r1, secp521r1
- AES
- SHA-1, SHA-2

TLS 1.2
- session resumption

TLS 1.3
- 0-RTT
- HelloRetryRequest


## Things to try

    swift run -c release tls client --connect swifttls.org

    swift run -c release tls server --port 4433 --certificate /path/to/mycert.pem --dhParameters /path/to/mydhparams.pem

BigInt performance highly depends on the build configuration, i.e. debug builds are an order of magnitude slower than release builds. So if you want to run the tests it is best to also use the release configuration like this:

    swift test -c release -Xswiftc -enable-testing

A test server is running at [swifttls.org](https://swifttls.org).

A good starting point to see how you set up a TLS connection in code is [server.swift](SwiftTLSTool/server.swift) and [client.swift](SwiftTLSTool/client.swift).

For a rough overview of the overall architecture see [SwiftTLS Design](Documentation/SwiftTLS%20Design.pdf)
## Disclaimer
Up until now this project has mainly been an effort for me to learn how TLS works, but I'd love to get your feedback and contributions to improve it.

Don't use this library in a production environment. It is not ready, has certainly a lot of bugs and received virtually no real world testing yet.

Performance has not been a primary goal until now, so don't expect too much.
