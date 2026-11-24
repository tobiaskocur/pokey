import PokeyCore
import PokeyPlatform
import PokeyRules
import Foundation
import ImageIO
import XPC

// pokey-inspector: the only process that parses untrusted bytes. Spawned by
// the sensor as root with the nonce pipe on fd 3. Order matters:
//   1. read nonce, drop to _pokeyinspect, verify root cannot be regained
//   2. hard rlimits
//   3. connect to the sensor, hello(nonce), receive init(rules fd)
//   4. load and self-test the rules (YARA compiles here), pre-warm ImageIO
//   5. sandbox_init(pure-computation), READY
//   6. one job: stage 1 (YARA-X + schemas) is delivered before stage 2 (ImageIO)
//   7. exit
// Any failure exits; the sensor turns the exit into an outcome.

let log = logger("inspector")

func die(_ why: String, code: Int32 = 2) -> Never {
    log.error("\(why, privacy: .public)")
    exit(code)
}

// MARK: 1. nonce and privilege drop

func readNonce() -> [UInt8] {
    var nonce = [UInt8](repeating: 0, count: InspectorProtocol.nonceLength)
    var got = 0
    while got < nonce.count {
        let n = nonce.withUnsafeMutableBytes { read(InspectorProtocol.nonceFD, $0.baseAddress! + got, $0.count - got) }
        if n < 0, errno == EINTR { continue }
        guard n > 0 else { die("nonce pipe") }
        got += n
    }
    close(InspectorProtocol.nonceFD)
    return nonce
}

func dropPrivileges() {
    guard getuid() == 0, geteuid() == 0 else { die("must be spawned by the root sensor") }
    guard let pw = getpwnam(InspectorProtocol.user) else { die("user \(InspectorProtocol.user) missing") }
    let uid = pw.pointee.pw_uid, gid = pw.pointee.pw_gid
    guard uid != 0, gid != 0 else { die("\(InspectorProtocol.user) must not be root") }
    var groups = [gid]
    guard setgroups(1, &groups) == 0, setgid(gid) == 0, setuid(uid) == 0 else { die("privilege drop failed") }
    guard setuid(0) != 0, seteuid(0) != 0, getuid() == uid, geteuid() == uid, getgid() == gid, getegid() == gid
    else { die("root could be regained") }
}

// MARK: 2. resource limits

func limit(_ resource: Int32, _ value: rlim_t) {
    var r = rlimit(rlim_cur: value, rlim_max: value)
    guard setrlimit(resource, &r) == 0 else { die("setrlimit \(resource)") }
}

func applyLimits() {
    limit(RLIMIT_CORE, 0)
    limit(RLIMIT_FSIZE, 0)   // no file writes
    limit(RLIMIT_NPROC, 0)   // no fork/spawn
    limit(RLIMIT_NOFILE, 64) // XPC + ImageIO need a few descriptors
    limit(RLIMIT_CPU, 120)   // backstop; the sensor's wall-clock watchdog is tighter
}

// MARK: 4. rules and pre-warm

struct Loaded {
    let bundle: RuleBundle
    let engine: ScanEngine
}

func readAll(fd: Int32, max: Int) throws -> [UInt8] {
    var st = stat()
    guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size > 0, st.st_size <= max else {
        throw ProtocolError("rules fd")
    }
    var buf = [UInt8](repeating: 0, count: Int(st.st_size))
    var off = 0
    while off < buf.count {
        let n = buf.withUnsafeMutableBytes { pread(fd, $0.baseAddress! + off, $0.count - off, off_t(off)) }
        if n < 0, errno == EINTR { continue }
        guard n > 0 else { throw ProtocolError("rules read") }
        off += n
    }
    return buf
}

func loadRules(_ msg: xpc_object_t) throws -> Loaded {
    let f = try Fields(XPCValue.decode(msg), required: ["type", "rules_fd", "roots", "threshold", "now"])
    try f.isFD("rules_fd")
    guard let roots = f.value("roots")?.array?.compactMap(\.data), roots.allSatisfy({ $0.count == 32 }) else {
        throw ProtocolError("roots")
    }
    let threshold = Int(try f.uint("threshold", max: 16))
    let fd = xpc_dictionary_dup_fd(msg, "rules_fd")
    guard fd >= 0 else { throw ProtocolError("rules_fd") }
    defer { close(fd) }
    let bytes = try readAll(fd: fd, max: NetdMessage.maxBundleBytes)
    let bundle = try RuleBundle(bytes: bytes, anchors: TrustAnchors(roots: roots, threshold: threshold),
                                now: Int64(Date().timeIntervalSince1970), mode: .load)
    let engine = try ScanEngine(bundle: bundle)
    try engine.selfTest(bundle: bundle)
    return Loaded(bundle: bundle, engine: engine)
}

/// Load the ImageIO codecs we may need before the sandbox closes: encode a
/// 2x2 image in each format and decode it again.
func prewarmImageIO() {
    let space = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(data: nil, width: 2, height: 2, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
          let image = ctx.makeImage()
    else { return }
    for type in ["public.png", "public.jpeg", "public.tiff", "com.compuserve.gif", "public.heic"] {
        let data = CFDataCreateMutable(nil, 0)!
        guard let dst = CGImageDestinationCreateWithData(data, type as CFString, 1, nil) else { continue }
        CGImageDestinationAddImage(dst, image, nil)
        guard CGImageDestinationFinalize(dst), let src = CGImageSourceCreateWithData(data, nil) else { continue }
        _ = CGImageSourceCreateImageAtIndex(src, 0, [kCGImageSourceShouldCacheImmediately: true] as CFDictionary)
    }
}

// MARK: 5. sandbox

@_silgen_name("sandbox_init")
func c_sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64,
                    _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
@_silgen_name("sandbox_free_error")
func c_sandbox_free_error(_ errorbuf: UnsafeMutablePointer<CChar>?)

/// kSBXProfilePureComputation with SANDBOX_NAMED: no file system, no network,
/// no new Mach lookups. Deprecated API, still enforced (accepted risk).
func enterSandbox() {
    var err: UnsafeMutablePointer<CChar>?
    guard c_sandbox_init("pure-computation", 1, &err) == 0 else {
        let text = err.map { String(cString: $0) } ?? "unknown"
        c_sandbox_free_error(err)
        die("sandbox_init: \(text)")
    }
}

// MARK: 6. job

struct Job {
    let id: UInt64
    let fd: Int32
    let size: UInt64
    let hint: String?
    let limits: JobLimits
}

func parseJob(_ msg: xpc_object_t) throws -> Job {
    let f = try Fields(XPCValue.decode(msg), required: ["type", "job_id", "file_fd", "size", "limits"],
                       optional: ["format_hint"])
    try f.isFD("file_fd")
    let limits = try JobLimits(f.value("limits") ?? .bool(false))
    let size = try f.uint("size", max: limits.maxBytes)
    let fd = xpc_dictionary_dup_fd(msg, "file_fd")
    guard fd >= 0 else { throw ProtocolError("file_fd") }
    return Job(id: try f.uint("job_id"), fd: fd, size: size, hint: try f.optionalString("format_hint", maxBytes: 32),
               limits: limits)
}

/// Read-only private mapping: clean file pages do not count against the
/// footprint limit. The file must still have the size the sensor hashed.
func mapFile(_ job: Job) throws -> UnsafeRawBufferPointer {
    var st = stat()
    guard fstat(job.fd, &st) == 0, UInt64(st.st_size) == job.size else { throw ProtocolError("file changed") }
    guard job.size > 0 else { return UnsafeRawBufferPointer(start: nil, count: 0) }
    let p = mmap(nil, Int(job.size), PROT_READ, MAP_PRIVATE, job.fd, 0)
    guard let p, p != MAP_FAILED else { throw ProtocolError("mmap") }
    return UnsafeRawBufferPointer(start: p, count: Int(job.size))
}

func stage2(_ data: UnsafeRawBufferPointer, job: Job) -> Stage2Reply {
    func reply(_ o: Outcome, _ w: UInt64 = 0, _ h: UInt64 = 0, frames: UInt64 = 0, detail: String) -> Stage2Reply {
        Stage2Reply(jobID: job.id, outcome: o, width: w, height: h, frames: frames, detail: detail)
    }
    guard let base = data.baseAddress,
          let cf = CFDataCreateWithBytesNoCopy(nil, base.assumingMemoryBound(to: UInt8.self), data.count, kCFAllocatorNull),
          let src = CGImageSourceCreateWithData(cf, [kCGImageSourceShouldCache: false] as CFDictionary)
    else { return reply(.decodeError, detail: "not an image") }
    let frames = UInt64(CGImageSourceGetCount(src))
    guard frames > 0,
          let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any],
          let w = (props[kCGImagePropertyPixelWidth] as? NSNumber)?.uint64Value,
          let h = (props[kCGImagePropertyPixelHeight] as? NSNumber)?.uint64Value, w > 0, h > 0
    else { return reply(.decodeError, frames: frames, detail: "no image properties") }
    let (pixels, overflow) = w.multipliedReportingOverflow(by: h)
    guard !overflow, pixels <= job.limits.maxPixels else {
        return reply(.resourceExceeded, w, h, frames: frames, detail: "\(w)x\(h) over the pixel limit")
    }
    let thumbOpts = [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceThumbnailMaxPixelSize: 256,
                     kCGImageSourceShouldCache: false] as CFDictionary
    guard CGImageSourceCreateThumbnailAtIndex(src, 0, thumbOpts) != nil else {
        return reply(.decodeError, w, h, frames: frames, detail: "thumbnail decode failed")
    }
    guard CGImageSourceCreateImageAtIndex(src, 0, [kCGImageSourceShouldCacheImmediately: true] as CFDictionary) != nil,
          CGImageSourceGetStatus(src) == .statusComplete
    else { return reply(.decodeError, w, h, frames: frames, detail: "full decode failed") }
    return reply(.clean, w, h, frames: frames, detail: "")
}

// MARK: main

let nonce = readNonce()
let config: PokeyConfig
do { config = try PokeyConfig.main() } catch { die("config: \(error)") }
dropPrivileges()
applyLimits()

let connQueue = DispatchQueue(label: "pokey.inspector.xpc")
let work = DispatchQueue(label: "pokey.inspector.work")
let conn = xpc_connection_create_mach_service(config.sensorMachService, connQueue,
                                              UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
guard xpc_connection_set_peer_code_signing_requirement(conn, config.requirement(.sensor)) == 0 else {
    die("peer requirement")
}
var loaded: Loaded?
var phase = 0 // 0 awaiting init, 1 awaiting job, 2 working

/// Send and wait until XPC has handed the message to the kernel, so a later
/// crash in a decoder cannot lose it.
func sendFlushed(_ v: Value) {
    xpc_connection_send_message(conn, XPCValue.encode(v))
    let done = DispatchSemaphore(value: 0)
    xpc_connection_send_barrier(conn) { done.signal() }
    done.wait()
}

xpc_connection_set_event_handler(conn) { msg in
    guard xpc_get_type(msg) == XPC_TYPE_DICTIONARY else { die("connection closed") }
    let type = xpc_dictionary_get_string(msg, "type").map { String(cString: $0) }
    switch (phase, type) {
    case (0, "init"):
        phase = 1
        work.async {
            do {
                loaded = try loadRules(msg)
            } catch {
                die("rules: \(error)")
            }
            prewarmImageIO()
            enterSandbox()
            sendFlushed(.dict(["type": .string("ready")]))
        }
    case (1, "job"):
        phase = 2
        work.async {
            guard let loaded else { die("job before rules") }
            let job: Job
            let data: UnsafeRawBufferPointer
            do {
                job = try parseJob(msg)
                data = try mapFile(job)
            } catch {
                die("job: \(error)")
            }
            let report = loaded.engine.scan(data, hint: job.hint)
            let s1 = report.stage1(jobID: job.id)
            sendFlushed(s1.value)
            if job.limits.decode, s1.outcome == .clean {
                sendFlushed(stage2(data, job: job).value)
            }
            exit(0)
        }
    default:
        die("unexpected message")
    }
}
xpc_connection_activate(conn)
sendFlushed(.dict(["type": .string("hello"), "nonce": .data(nonce)]))
dispatchMain()
