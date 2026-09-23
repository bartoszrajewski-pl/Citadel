import Crypto
import Foundation
import NIO

// ECDSA keys in OpenSSH's private key format, for P-256, P-384 and P-521.
//
// The container — cipher, KDF, check bytes, padding — is handled by the generic
// `OpenSSH.PrivateKey`, so encrypted keys work exactly as ed25519 and RSA do.
// What an ECDSA key adds is its payload:
//
//   public key:  string curve ("nistp256")  string Q (uncompressed point)
//   private key: string curve               string Q    mpint d
//
// `d` is an SSH mpint: big-endian, with a leading zero byte when its top bit is
// set and without leading zeros otherwise, so it is normalised to the curve's
// fixed scalar size before CryptoKit sees it.

/// One curve's worth of CryptoKit, so the three conformances share one reader.
private struct ECDSACurve {
    let name: String
    let scalarSize: Int
}

private func readECDSAPublicPoint(curve: ECDSACurve, consuming buffer: inout ByteBuffer) throws -> [UInt8] {
    guard let name = buffer.readSSHString(), name == curve.name else {
        throw InvalidOpenSSHKey.invalidPublicKeyPrefix
    }
    guard var point = buffer.readSSHBuffer(), let bytes = point.readBytes(length: point.readableBytes) else {
        throw InvalidOpenSSHKey.missingPublicKeyBuffer
    }
    return bytes
}

private func readECDSAPrivateScalar(curve: ECDSACurve, consuming buffer: inout ByteBuffer) throws -> (scalar: [UInt8], point: [UInt8]) {
    let point = try readECDSAPublicPoint(curve: curve, consuming: &buffer)
    guard var mpint = buffer.readSSHBuffer(), var d = mpint.readBytes(length: mpint.readableBytes) else {
        throw InvalidOpenSSHKey.missingPrivateKeyBuffer
    }
    while d.count > curve.scalarSize, d.first == 0 { d.removeFirst() }
    guard d.count <= curve.scalarSize else { throw InvalidOpenSSHKey.missingPrivateKeyBuffer }
    return (Array(repeating: 0, count: curve.scalarSize - d.count) + d, point)
}

private func writeECDSAPublic(curve: ECDSACurve, point: Data, to buffer: inout ByteBuffer) -> Int {
    let start = buffer.writerIndex
    buffer.writeSSHString(curve.name)
    buffer.writeSSHString(Array(point))
    return buffer.writerIndex - start
}

private let nistp256 = ECDSACurve(name: "nistp256", scalarSize: 32)
private let nistp384 = ECDSACurve(name: "nistp384", scalarSize: 48)
private let nistp521 = ECDSACurve(name: "nistp521", scalarSize: 66)

// MARK: - P-256

extension P256.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        try Self(x963Representation: readECDSAPublicPoint(curve: nistp256, consuming: &buffer))
    }
    func write(to buffer: inout ByteBuffer) -> Int {
        writeECDSAPublic(curve: nistp256, point: x963Representation, to: &buffer)
    }
}

extension P256.Signing.PrivateKey: ByteBufferConvertible, OpenSSHPrivateKey {
    typealias PublicKey = P256.Signing.PublicKey
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp256" }
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp256" }
    static var keyType: OpenSSH.KeyType { .ecdsaP256 }

    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (d, q) = try readECDSAPrivateScalar(curve: nistp256, consuming: &buffer)
        let key = try Self(rawRepresentation: d)
        guard Array(key.publicKey.x963Representation) == q else { throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey }
        return key
    }
    func write(to buffer: inout ByteBuffer) -> Int { publicKey.write(to: &buffer) }

    /// Creates a P-256 key from an OpenSSH private key (`ssh-keygen -t ecdsa -b 256`).
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P256.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
    }
}

// MARK: - P-384

extension P384.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        try Self(x963Representation: readECDSAPublicPoint(curve: nistp384, consuming: &buffer))
    }
    func write(to buffer: inout ByteBuffer) -> Int {
        writeECDSAPublic(curve: nistp384, point: x963Representation, to: &buffer)
    }
}

extension P384.Signing.PrivateKey: ByteBufferConvertible, OpenSSHPrivateKey {
    typealias PublicKey = P384.Signing.PublicKey
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp384" }
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp384" }
    static var keyType: OpenSSH.KeyType { .ecdsaP384 }

    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (d, q) = try readECDSAPrivateScalar(curve: nistp384, consuming: &buffer)
        let key = try Self(rawRepresentation: d)
        guard Array(key.publicKey.x963Representation) == q else { throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey }
        return key
    }
    func write(to buffer: inout ByteBuffer) -> Int { publicKey.write(to: &buffer) }

    /// Creates a P-384 key from an OpenSSH private key (`ssh-keygen -t ecdsa -b 384`).
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P384.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
    }
}

// MARK: - P-521

extension P521.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        try Self(x963Representation: readECDSAPublicPoint(curve: nistp521, consuming: &buffer))
    }
    func write(to buffer: inout ByteBuffer) -> Int {
        writeECDSAPublic(curve: nistp521, point: x963Representation, to: &buffer)
    }
}

extension P521.Signing.PrivateKey: ByteBufferConvertible, OpenSSHPrivateKey {
    typealias PublicKey = P521.Signing.PublicKey
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp521" }
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp521" }
    static var keyType: OpenSSH.KeyType { .ecdsaP521 }

    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (d, q) = try readECDSAPrivateScalar(curve: nistp521, consuming: &buffer)
        let key = try Self(rawRepresentation: d)
        guard Array(key.publicKey.x963Representation) == q else { throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey }
        return key
    }
    func write(to buffer: inout ByteBuffer) -> Int { publicKey.write(to: &buffer) }

    /// Creates a P-521 key from an OpenSSH private key (`ssh-keygen -t ecdsa -b 521`).
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P521.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
    }
}
