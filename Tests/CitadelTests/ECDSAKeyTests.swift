import Crypto
import Foundation
import XCTest
@testable import Citadel

/// ECDSA keys exactly as OpenSSH writes them today, generated per run.
final class ECDSAKeyTests: XCTestCase {
    private func generate(bits: Int, passphrase: String) throws -> String {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("ecdsa-\(UUID())").path
        defer { try? FileManager.default.removeItem(atPath: path); try? FileManager.default.removeItem(atPath: path + ".pub") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-q", "-t", "ecdsa", "-b", "\(bits)", "-N", passphrase, "-f", path]
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0)
        return try String(contentsOfFile: path, encoding: .utf8)
    }

    func testAllThreeCurvesParse() throws {
        _ = try P256.Signing.PrivateKey(sshECDSA: generate(bits: 256, passphrase: ""))
        _ = try P384.Signing.PrivateKey(sshECDSA: generate(bits: 384, passphrase: ""))
        _ = try P521.Signing.PrivateKey(sshECDSA: generate(bits: 521, passphrase: ""))
    }

    func testEncryptedKeysParseWithTheirPassphrase() throws {
        let pw = Data("correct horse".utf8)
        _ = try P256.Signing.PrivateKey(sshECDSA: generate(bits: 256, passphrase: "correct horse"), decryptionKey: pw)
        _ = try P521.Signing.PrivateKey(sshECDSA: generate(bits: 521, passphrase: "correct horse"), decryptionKey: pw)
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshECDSA: generate(bits: 256, passphrase: "x")))
    }

    /// A key of one curve must not be accepted as another.
    func testTheWrongCurveIsRefused() throws {
        let p384 = try generate(bits: 384, passphrase: "")
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshECDSA: p384))
    }

    /// The parsed key must be the key in the file: it signs, and verifies.
    func testTheParsedKeySigns() throws {
        let key = try P256.Signing.PrivateKey(sshECDSA: generate(bits: 256, passphrase: ""))
        let message = Data("halyard".utf8)
        XCTAssertTrue(key.publicKey.isValidSignature(try key.signature(for: message), for: message))
    }
}
