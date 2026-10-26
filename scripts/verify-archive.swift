import Foundation
import CryptoKit
let args = CommandLine.arguments
 guard args.count == 4, let signature = Data(base64Encoded: args[2]), let publicBytes = Data(base64Encoded: args[3]) else { exit(2) }
let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicBytes)
let bytes = try Data(contentsOf: URL(fileURLWithPath: args[1]))
guard key.isValidSignature(signature, for: bytes) else { fputs("Invalid update signature\n", stderr); exit(1) }
print("Update archive signature verified against pinned public key")
