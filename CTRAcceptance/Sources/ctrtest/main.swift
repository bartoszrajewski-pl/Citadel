import Citadel
import Darwin
import Crypto
import Foundation
import NIOCore
import NIOSSH

// The server under test offers aes128-ctr and nothing else, so reaching it at
// all proves the cipher ran. Key exchange stays at its defaults: SSHAlgorithms
// .all adds DH group14, which OpenSSH 10.2 no longer offers, and that fails
// negotiation before any cipher is considered.
setvbuf(stdout, nil, _IONBF, 0)

var ctrOnly = SSHAlgorithms()
ctrOnly.transportProtectionSchemes = .add([AES128CTR.self])

let env = ProcessInfo.processInfo.environment
let host = env["CTR_HOST"] ?? "127.0.0.1"
let port = Int(env["CTR_PORT"] ?? "62203")!
let user = env["CTR_USER"] ?? NSUserName()
let keyPath = env["CTR_KEY"]!

let key = try Curve25519.Signing.PrivateKey(sshEd25519: String(contentsOfFile: keyPath, encoding: .utf8))
let client = try await SSHClient.connect(
    host: host, port: port,
    authenticationMethod: .ed25519(username: user, privateKey: key),
    hostKeyValidator: .acceptAnything(),
    reconnect: .never,
    algorithms: ctrOnly
)
print("[0] connected to a server that offers only aes128-ctr")

// 1. a command, round-tripped. mergeStreams because a login that chatters on
//    stderr otherwise surfaces as TTYSTDError and stops the run at the door.
let out = try await client.executeCommand("echo halyard-ctr-ok; uname -s", mergeStreams: true)
print("[1] command: \(String(buffer: out).trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\n", with: " / "))")

// 2. a long stream: a wrong counter survives a short exchange and corrupts a
//    long one, so push enough bytes through to catch that.
let bulkStart = Date()
let big = try await client.executeCommand("head -c 3000000 /dev/urandom | base64", mergeStreams: true)
print("[2] bulk: \(big.readableBytes) bytes back in \(String(format: "%.1f", Date().timeIntervalSince(bulkStart)))s")
guard big.readableBytes > 4_000_000 else { fatalError("[2] FAIL: short read") }

// 3. checksum end to end, so "intact" means the bytes and not just the count.
//    A deterministic stream, hashed on both ends and compared.
let gen = "head -c 4000000 /dev/zero | base64"
let payload = try await client.executeCommand(gen, mergeStreams: true)
let remoteSum = try await client.executeCommand("\(gen) | md5", mergeStreams: true)
let localSum = Insecure.MD5.hash(data: Data(payload.readableBytesView)).map { String(format: "%02x", $0) }.joined()
let expected = String(buffer: remoteSum).trimmingCharacters(in: .whitespacesAndNewlines)
print("[3] checksum: local \(localSum) vs remote \(expected)")
guard localSum == expected else { fatalError("[3] FAIL: \(payload.readableBytes) bytes arrived corrupted") }

// 4. the same thing an order of magnitude larger. Whether this crosses a
//    rekey depends on the server it is pointed at — run.sh points it at the
//    no-rekey one, so do not read this as the rekey check. That one is
//    rekeyprobe with IDLE set, against a server on a rekey timer.
let bigGen = "head -c 8000000 /dev/zero | base64"
let bigPayload = try await client.executeCommand(bigGen, mergeStreams: true)
let bigRemote = try await client.executeCommand("\(bigGen) | md5", mergeStreams: true)
let bigLocal = Insecure.MD5.hash(data: Data(bigPayload.readableBytesView)).map { String(format: "%02x", $0) }.joined()
let bigExpected = String(buffer: bigRemote).trimmingCharacters(in: .whitespacesAndNewlines)
print("[4] larger stream: \(bigPayload.readableBytes) bytes, local \(bigLocal) vs remote \(bigExpected)")
guard bigLocal == bigExpected else { fatalError("[4] FAIL: corruption in a 10MB stream") }

// 5. SFTP, the other half of the acceptance list in docs/aes128-ctr-port.md
let sftp = try await client.openSFTP()
let remotePath = "/tmp/ctr-sftp-probe.bin"
let file = try await sftp.openFile(filePath: remotePath, flags: [.write, .create, .truncate])
var blob = ByteBuffer()
for i in 0..<2_000_000 { blob.writeInteger(UInt8(truncatingIfNeeded: i &* 31 &+ 7)) }
try await file.write(blob)
try await file.close()
let readBack = try await sftp.withFile(filePath: remotePath, flags: .read) { try await $0.readAll() }
print("[5] sftp: wrote \(blob.readableBytes), read back \(readBack.readableBytes)")
guard Data(readBack.readableBytesView) == Data(blob.readableBytesView) else { fatalError("[5] FAIL: sftp round trip differs") }
_ = try? await sftp.remove(at: remotePath)
try await sftp.close()

try await client.close()
print("[6] closed cleanly — all checks passed")
