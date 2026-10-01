import Crypto
import Foundation
import NIOSSH
import XCTest
@testable import Citadel

/// RSA keys sign in as rsa-sha2-512. They used to sign as ssh-rsa (SHA-1),
/// which OpenSSH 8.8 and newer refuse by default, so an RSA key plain `ssh`
/// logs in with was turned away ("signature algorithm ssh-rsa not in
/// PubkeyAcceptedAlgorithms").
final class RSAUserAuthTests: XCTestCase {
    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("rsa-auth-\(UUID())")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    @discardableResult
    private func run(_ tool: String, _ arguments: [String]) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = arguments
        try p.run(); p.waitUntilExit()
        return p
    }

    /// A fresh key pair, written by ssh-keygen; returns the private key's path.
    private func keyPair(_ type: String, _ name: String) throws -> String {
        let path = scratch.appendingPathComponent(name).path
        XCTAssertEqual(try run("/usr/bin/ssh-keygen", ["-q", "-t", type, "-N", "", "-f", path]).terminationStatus, 0)
        return path
    }

    func testTheSignatureIsRSASHA512AndVerifies() throws {
        let key = try Insecure.RSA.PrivateKey(sshRsa: String(contentsOfFile: keyPair("rsa", "id_rsa"), encoding: .utf8))
        XCTAssertEqual(Insecure.RSA.PrivateKey.userAuthAlgorithmName, "rsa-sha2-512")
        XCTAssertEqual(Insecure.RSA.PrivateKey.keyPrefix, "ssh-rsa", "the key blob keeps its own name")

        let message = Data("session id and request".utf8)
        let signature: Insecure.RSA.SHA512Signature = try key.signature(for: message)
        XCTAssertEqual(type(of: signature).signaturePrefix, "rsa-sha2-512")
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(key.publicKey.isValidSignature(signature, for: Data("something else".utf8)))
    }

    /// The real thing: log in to a throwaway OpenSSH server, which refuses
    /// ssh-rsa signatures, with an RSA key.
    func testAnRSAKeyLogsInToCurrentOpenSSH() async throws {
        let sshd = "/usr/sbin/sshd"
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: sshd), "no sshd on this machine")

        let hostKey = try keyPair("ed25519", "host")
        let client = try keyPair("rsa", "client")
        let authorized = scratch.appendingPathComponent("authorized_keys")
        try FileManager.default.copyItem(atPath: client + ".pub", toPath: authorized.path)

        let port = Int.random(in: 40_000..<60_000)
        let config = scratch.appendingPathComponent("sshd_config")
        try """
        Port \(port)
        ListenAddress 127.0.0.1
        HostKey \(hostKey)
        AuthorizedKeysFile \(authorized.path)
        PidFile \(scratch.appendingPathComponent("sshd.pid").path)
        UsePAM no
        StrictModes no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        """.write(to: config, atomically: true, encoding: .utf8)

        let server = Process()
        server.executableURL = URL(fileURLWithPath: sshd)
        server.arguments = ["-D", "-e", "-f", config.path]
        server.standardError = FileHandle.nullDevice
        try server.run()
        defer { server.terminate(); server.waitUntilExit() }

        // sshd takes a moment to listen, and a slow first run took longer than
        // a fixed wait. Retry the connect for up to five seconds; a refused
        // login is still a failure on the last attempt.
        let key = try Insecure.RSA.PrivateKey(sshRsa: String(contentsOfFile: client, encoding: .utf8))
        var ssh: SSHClient?
        var lastError: Error?
        for _ in 0..<25 where ssh == nil {
            do {
                ssh = try await SSHClient.connect(
                    host: "127.0.0.1",
                    port: port,
                    authenticationMethod: .rsa(username: NSUserName(), privateKey: key),
                    hostKeyValidator: .acceptAnything(),
                    reconnect: .never
                )
            } catch {
                lastError = error
                try await Task.sleep(nanoseconds: 200_000_000)
            }
        }
        guard let ssh else { throw lastError! }
        let output = try await ssh.executeCommand("echo signed-in")
        try await ssh.close()
        XCTAssertEqual(String(buffer: output).trimmingCharacters(in: .whitespacesAndNewlines), "signed-in")
    }
}
