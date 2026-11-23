import CryptoKit
import EDRCore
import EDRPlatform
import Foundation

// edr-netd: LaunchDaemon (SMAppService.daemon) running as _edrnet. The only
// process with network access. It fetches rule bundles and forwards the bytes
// unparsed to the sensor, which verifies them; and it ships the sensor's
// telemetry spool (hashes and metadata only), acknowledging what was accepted.
// It has no Full Disk Access and writes nothing.

let log = logger("netd")

struct NetdConfig {
    let rulesURL: URL
    let telemetryURL: URL?
    let rulesInterval: TimeInterval
    let telemetryInterval: TimeInterval

    init(info: [String: Any]) throws {
        func https(_ key: String) throws -> URL? {
            guard let s = info[key] as? String, !s.isEmpty else { return nil }
            guard let u = URL(string: s), u.scheme == "https", u.host != nil else {
                throw ConfigError("\(key) must be an https URL")
            }
            return u
        }
        guard let rules = try https("EDRRulesURL") else { throw ConfigError("EDRRulesURL missing from Info.plist") }
        rulesURL = rules
        telemetryURL = try https("EDRTelemetryURL")
        rulesInterval = TimeInterval(max(300, plistInt(info, "EDRRulesIntervalSeconds") ?? 3600))
        telemetryInterval = TimeInterval(max(30, plistInt(info, "EDRTelemetryIntervalSeconds") ?? 60))
    }
}

struct NetError: Error, CustomStringConvertible {
    var description: String
    init(_ d: String) { description = d }
}

/// Refuses redirects that leave https.
final class HTTPSOnly: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme == "https" ? request : nil)
    }
}

let session: URLSession = {
    let c = URLSessionConfiguration.ephemeral
    c.timeoutIntervalForRequest = 60
    c.timeoutIntervalForResource = 300
    c.urlCache = nil
    c.httpCookieStorage = nil
    c.httpShouldSetCookies = false
    return URLSession(configuration: c, delegate: HTTPSOnly(), delegateQueue: nil)
}()

let sensorQueue = DispatchQueue(label: "edr.netd.sensor")

/// The XPC call blocks, so it runs off the cooperative thread pool.
func ask(_ client: SensorClient, _ m: NetdMessage, maxReplyData: Int = MessageLimits.maxData) async throws -> Value {
    try await withCheckedThrowingContinuation { cont in
        sensorQueue.async { cont.resume(with: Result { try client.request(m.value, maxReplyData: maxReplyData) }) }
    }
}

/// GET the bundle with a hard size cap; nil when unchanged (304).
func fetchBundle(_ url: URL, etag: String?) async throws -> (bytes: [UInt8], etag: String?)? {
    var req = URLRequest(url: url)
    if let etag { req.setValue(etag, forHTTPHeaderField: "If-None-Match") }
    let (stream, resp) = try await session.bytes(for: req)
    guard let http = resp as? HTTPURLResponse else { throw NetError("not HTTP") }
    if http.statusCode == 304 { return nil }
    guard http.statusCode == 200 else { throw NetError("HTTP \(http.statusCode)") }
    let limit = NetdMessage.maxBundleBytes
    guard http.expectedContentLength <= Int64(limit) else { throw NetError("bundle larger than \(limit) bytes") }
    var out: [UInt8] = []
    out.reserveCapacity(Int(max(0, http.expectedContentLength)))
    for try await b in stream {
        guard out.count < limit else { throw NetError("bundle larger than \(limit) bytes") }
        out.append(b)
    }
    return (out, http.value(forHTTPHeaderField: "ETag"))
}

actor RulesState {
    var etag: String?
    var lastDigest: SHA256.Digest?
    func update(etag: String?, digest: SHA256.Digest) { self.etag = etag; lastDigest = digest }
}

func syncRules(_ cfg: NetdConfig, _ client: SensorClient, _ state: RulesState) async {
    do {
        guard let fetched = try await fetchBundle(cfg.rulesURL, etag: await state.etag) else { return }
        let (bytes, etag) = fetched
        let digest = SHA256.hash(data: bytes)
        // Do not re-offer bytes the sensor already accepted or rejected.
        guard await state.lastDigest != digest, !bytes.isEmpty else {
            await state.update(etag: etag, digest: digest)
            return
        }
        let reply = try Fields(await ask(client, .bundle(bytes)), required: ["ok", "error"])
        await state.update(etag: etag, digest: digest)
        if reply.value("ok") == .bool(true) {
            log.notice("sensor accepted rule bundle \(digest.description, privacy: .public)")
        } else {
            log.error("sensor rejected rule bundle: \(try reply.string("error"), privacy: .public)")
        }
    } catch {
        log.error("rule sync failed: \(String(describing: error), privacy: .public)")
    }
}

func shipTelemetry(_ url: URL, _ client: SensorClient) async {
    do {
        while true {
            let reply = try Fields(await ask(client, .telemetryPull(max: NetdMessage.maxPull), maxReplyData: 16 << 20),
                                   required: ["up_to", "data"])
            let upTo = try reply.uint("up_to", max: UInt64(Int64.max))
            guard upTo > 0, let body = reply.value("data")?.data else { return }
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let (_, resp) = try await session.upload(for: req, from: Data(body))
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw NetError("telemetry endpoint answered \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
            }
            _ = try Fields(await ask(client, .telemetryAck(upTo: Int64(upTo))), required: ["ok"])
        }
    } catch {
        log.error("telemetry upload failed: \(String(describing: error), privacy: .public)")
    }
}

func every(_ seconds: TimeInterval, _ body: @escaping @Sendable () async -> Void) -> Task<Void, Never> {
    Task {
        while !Task.isCancelled {
            await body()
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1e9))
        }
    }
}

do {
    let info = Bundle.main.infoDictionary ?? [:]
    let config = try EDRConfig(info: info)
    let cfg = try NetdConfig(info: info)
    let client = SensorClient(config: config)
    let rules = RulesState()
    _ = every(cfg.rulesInterval) { await syncRules(cfg, client, rules) }
    if let url = cfg.telemetryURL {
        _ = every(cfg.telemetryInterval) { await shipTelemetry(url, client) }
    }
} catch {
    log.fault("edr-netd failed to start: \(String(describing: error), privacy: .public)")
    exit(1)
}
dispatchMain()
