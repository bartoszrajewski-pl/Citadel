import Citadel
import Crypto
import Darwin
import Foundation
import NIOCore
import NIOSSH

setvbuf(stdout, nil, _IONBF, 0)

// One connection, N identical checksummed reads. With the server's RekeyLimit
// low, each read spans several updateKeys, so a counter that does not survive a
// key update shows up as a checksum mismatch; a stall shows up as a timeout on
// one iteration instead of hanging the run.
var algos = SSHAlgorithms()
algos.transportProtectionSchemes = .add([AES128CTR.self])

let env = ProcessInfo.processInfo.environment
let port = Int(env["CTR_PORT"] ?? "62203")!
let iterations = Int(env["ITERATIONS"] ?? "8")!
let bytes = env["BYTES"] ?? "2000000"
let label = env["LABEL"] ?? "run"
let key = try Curve25519.Signing.PrivateKey(sshEd25519: String(contentsOfFile: env["CTR_KEY"]!, encoding: .utf8))

struct Timeout: Error {}
func withWatchdog<T: Sendable>(_ seconds: Int, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            throw Timeout()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

let client = try await SSHClient.connect(
    host: "127.0.0.1", port: port,
    authenticationMethod: .ed25519(username: NSUserName(), privateKey: key),
    hostKeyValidator: .acceptAnything(), reconnect: .never, algorithms: algos
)
let gen = "head -c \(bytes) /dev/zero | base64"
let expected = String(buffer: try await client.executeCommand("\(gen) | md5", mergeStreams: true))
    .trimmingCharacters(in: .whitespacesAndNewlines)
print("\(label): expecting \(expected) per iteration")

if let idle = Int(env["IDLE"] ?? "") {
    print("\(label): idling \(idle)s so the server's timer forces a rekey on a quiet connection")
    try await Task.sleep(nanoseconds: UInt64(idle) * 1_000_000_000)
    print("\(label): resuming; everything below rides on keys installed by updateKeys")
}

var passed = 0, mismatched = 0, stalled = 0
for i in 1...iterations {
    let started = Date()
    do {
        let buf = try await withWatchdog(45) { try await client.executeCommand(gen, mergeStreams: true) }
        let got = Insecure.MD5.hash(data: Data(buf.readableBytesView)).map { String(format: "%02x", $0) }.joined()
        let secs = String(format: "%.1f", Date().timeIntervalSince(started))
        if got == expected {
            passed += 1
            print("\(label) [\(i)/\(iterations)] ok   \(buf.readableBytes) bytes in \(secs)s")
        } else {
            mismatched += 1
            print("\(label) [\(i)/\(iterations)] CORRUPT \(buf.readableBytes) bytes, md5 \(got)")
        }
    } catch is Timeout {
        stalled += 1
        print("\(label) [\(i)/\(iterations)] STALLED (no completion in 45s)")
        break
    } catch {
        print("\(label) [\(i)/\(iterations)] ERROR \(error)")
        break
    }
}
print("\(label): RESULT passed=\(passed) corrupt=\(mismatched) stalled=\(stalled)")
try? await client.close()
