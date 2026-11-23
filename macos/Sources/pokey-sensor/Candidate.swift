import CryptoKit
import PokeyCore
import Foundation

/// A file that passed every cheap check and is ready for inspection. Owns the
/// read-only descriptor that is handed to the inspector.
final class Candidate {
    let fd: Int32
    let key: FileKey
    let path: String
    let size: UInt64
    let sha256: [UInt8]
    let quarantine: QuarantineInfo
    let whereFroms: [UInt8]?
    private let changeStamp: [Int]

    var shaHex: String { sha256.map { String(format: "%02x", $0) }.joined() }

    private init(fd: Int32, key: FileKey, path: String, size: UInt64, sha256: [UInt8], quarantine: QuarantineInfo,
                 whereFroms: [UInt8]?, changeStamp: [Int]) {
        self.fd = fd; self.key = key; self.path = path; self.size = size; self.sha256 = sha256
        self.quarantine = quarantine; self.whereFroms = whereFroms; self.changeStamp = changeStamp
    }

    /// True if the content cannot have changed since hashing (same size and
    /// ctime/mtime). Otherwise the verdict must not be cached under `sha256`:
    /// the inspector may have read different bytes.
    func unchangedSinceHash() -> Bool {
        var st = stat()
        return fstat(fd, &st) == 0 && Self.stamp(st) == changeStamp
    }

    private static func stamp(_ st: stat) -> [Int] {
        [Int(st.st_size), st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec, st.st_ctimespec.tv_sec, st.st_ctimespec.tv_nsec]
    }

    deinit { close(fd) }

    enum Skip: Error, Equatable {
        case openFailed(Int32), notRegular, identityChanged, dataless, noQuarantine, badQuarantine, tooLarge, readFailed
    }

    static let quarantineXattr = "com.apple.quarantine"
    static let whereFromsXattr = "com.apple.metadata:kMDItemWhereFroms"
    static let maxWhereFroms = 4096
    private static let sfDataless: UInt32 = 0x4000_0000 // SF_DATALESS, sys/stat.h

    /// Open by path and check that it is still the file the event named.
    /// `maxBytes(size)` returns the policy limit for this file.
    static func open(key: FileKey, path: String, maxBytes: UInt64) throws -> Candidate {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Skip.openFailed(errno) }
        var ok = false
        defer { if !ok { close(fd) } }

        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw Skip.notRegular }
        guard UInt64(UInt32(bitPattern: st.st_dev)) == key.dev, st.st_ino == key.ino else { throw Skip.identityChanged }
        guard st.st_flags & sfDataless == 0 else { throw Skip.dataless }

        var qbuf = [UInt8](repeating: 0, count: QuarantineInfo.maxLength)
        let qn = fgetxattr(fd, quarantineXattr, &qbuf, qbuf.count, 0, 0)
        guard qn > 0 else { throw Skip.noQuarantine }
        guard let q = QuarantineInfo(xattr: Array(qbuf.prefix(qn))) else { throw Skip.badQuarantine }

        let size = UInt64(st.st_size)
        guard size <= maxBytes else { throw Skip.tooLarge }

        var wbuf = [UInt8](repeating: 0, count: maxWhereFroms)
        let wn = fgetxattr(fd, whereFromsXattr, &wbuf, wbuf.count, 0, 0)

        let sha = try hash(fd: fd, size: size)
        ok = true
        return Candidate(fd: fd, key: key, path: path, size: size, sha256: sha, quarantine: q,
                         whereFroms: wn > 0 ? Array(wbuf.prefix(wn)) : nil, changeStamp: stamp(st))
    }

    /// Streamed SHA-256 with pread (the descriptor offset stays at 0).
    private static func hash(fd: Int32, size: UInt64) throws -> [UInt8] {
        var h = SHA256()
        var buf = [UInt8](repeating: 0, count: 1 << 20)
        var off: off_t = 0
        while UInt64(off) < size {
            let n = buf.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, off) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { throw Skip.readFailed }
            buf.withUnsafeBytes { h.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0.prefix(n))) }
            off += off_t(n)
        }
        return Array(h.finalize())
    }
}
