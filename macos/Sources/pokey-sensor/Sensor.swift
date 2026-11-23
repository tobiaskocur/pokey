import PokeyCore
import PokeyPlatform
import PokeyRules
import Foundation

/// The sensor pipeline. Everything below runs on one serial queue:
///
///     ES event -> debounce (dev, ino) -> ready FIFO (bounded) -> open, identity,
///     quarantine, size, SHA-256 -> verdict cache -> journal -> inspector
///     (watchdog) -> bundle policy -> event store, telemetry spool, cache.
///
/// At most `maxInFlight` candidates hold an open descriptor at a time; the
/// rest wait as (dev, ino, path) only. The sensor never reads file contents
/// except to hash them.
final class Sensor {
    static let maxInFlight = 2
    static let readyCapacity = 10_000
    static let expiryCheckSeconds = 3600

    private let config: PokeyConfig
    private let queue = DispatchQueue(label: "pokey.sensor.pipeline", qos: .utility)
    private let log = logger("sensor")
    private let store: Store
    private let rules: RulesStore
    private let anchors: TrustAnchors
    private let pool: InspectorPool
    private let server: XPCServer
    private let telemetryWhereFroms: Bool
    private var es: ESClient?

    private var bundle: RuleBundle?
    private var gate: HealthGate?
    private var activating = false
    private var staleAlerted: UInt64?
    private var debouncer = Debouncer<String>()
    private var debounceTimer: DispatchSourceTimer?
    private var expiryTimer: DispatchSourceTimer?
    private var ready: [(FileKey, String)] = []
    private var readyDropped: UInt64 = 0
    private var inFlight = 0
    private var cache = VerdictCache()

    init(config: PokeyConfig) throws {
        self.config = config
        let state = config.stateDirectory
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        chmod(state.path, 0o700)
        store = try Store(path: state.appendingPathComponent("sensor.sqlite").path)
        rules = try RulesStore(root: state.appendingPathComponent("Rules", isDirectory: true))

        let info = Bundle.main.infoDictionary ?? [:]
        guard let rootsURL = Bundle.main.url(forResource: "trust-roots", withExtension: "txt"),
              let threshold = plistInt(info, "PokeyRootThreshold"), threshold > 0
        else { throw ConfigError("trust-roots.txt or PokeyRootThreshold missing from the sensor bundle") }
        anchors = try TrustAnchors(text: String(contentsOf: rootsURL, encoding: .utf8), threshold: threshold)
        guard anchors.roots.count >= threshold else { throw ConfigError("fewer root keys than the threshold") }
        telemetryWhereFroms = plistBool(info, "PokeyTelemetryWhereFroms")

        guard let inspector = Bundle.main.url(forAuxiliaryExecutable: "pokey-inspector") else {
            throw ConfigError("pokey-inspector missing from the sensor bundle")
        }
        pool = InspectorPool(queue: queue, executable: inspector.path)
        server = XPCServer(config: config, queue: queue)
    }

    func start() throws {
        // Never trigger iCloud/File Provider downloads; dataless files are skipped.
        guard setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS,
                             IOPOL_MATERIALIZE_DATALESS_FILES_OFF) == 0
        else { throw ConfigError("setiopolicy_np(dataless off) failed: errno \(errno)") }

        queue.sync {
            loadCurrentRules()
            recoverJournal()
        }

        server.attach = { [unowned self] role, conn in attach(role, conn) }
        server.handle = { [unowned self] role, conn, msg in handle(role, conn, msg) }
        server.disconnected = { [unowned self] role, conn in if role == .inspector { pool.disconnected(conn) } }
        server.start()

        let es = ESClient(queue: queue, sink: { [unowned self] in offer($0) }, onExit: { _ in })
        try es.start()
        self.es = es

        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(Self.expiryCheckSeconds), repeating: .seconds(Self.expiryCheckSeconds))
        t.setEventHandler { [unowned self] in checkExpiry() }
        t.resume()
        expiryTimer = t
    }

    // MARK: rules

    private func inspectorRules(_ b: RuleBundle) -> InspectorPool.Rules {
        InspectorPool.Rules(path: rules.bundleURL(b.info.version), anchors: anchors.roots,
                            threshold: anchors.threshold, memoryLimitMB: b.info.memoryLimitMB)
    }

    private func use(_ b: RuleBundle) {
        bundle = b
        pool.rulesChanged(inspectorRules(b))
        checkExpiry()
        pump()
    }

    private func loadCurrentRules() {
        do {
            guard let (version, bytes) = try rules.currentBundle() else {
                log.notice("no rules installed yet; waiting for pokey-netd")
                return
            }
            let b = try RuleBundle(bytes: [UInt8](bytes), anchors: anchors, now: now(), mode: .load)
            guard b.info.version == version else { throw ConfigError("bundle version does not match its directory") }
            use(b)
            log.info("loaded rules version \(version)")
        } catch {
            log.error("current rules failed to load: \(String(describing: error), privacy: .public)")
            rollback(reason: "current rules failed to load: \(error)")
        }
    }

    /// Expired rules keep scanning; the user is told once per version.
    private func checkExpiry() {
        guard let b = bundle, now() >= b.info.expires, staleAlerted != b.info.version else { return }
        staleAlerted = b.info.version
        alert("Rules version \(b.info.version) expired; scanning continues with stale rules until an update arrives.")
    }

    /// netd delivered a bundle: verify (signatures first, then manifest,
    /// version > high-water, not expired), store read-only, self-test in a
    /// fresh inspector, then switch atomically and start the health gate.
    private func activate(_ bytes: [UInt8], reply: @escaping (String?) -> Void) {
        guard !activating else { return reply("activation already in progress") }
        let highWater = rules.state.highWater
        let b: RuleBundle
        do {
            b = try RuleBundle(bytes: bytes, anchors: anchors, now: now(),
                               mode: .activation(currentVersion: highWater == 0 ? nil : highWater))
            try rules.install(version: b.info.version, bytes: Data(bytes))
        } catch {
            log.error("rejected rule bundle: \(String(describing: error), privacy: .public)")
            return reply(String(describing: error))
        }
        activating = true
        let version = b.info.version
        pool.probe(rules: inspectorRules(b)) { [unowned self] ok in
            activating = false
            guard ok else {
                log.error("rules version \(version) failed the inspector self-test")
                return reply("self-test failed")
            }
            do {
                try rules.activate(version: version)
            } catch {
                return reply(String(describing: error))
            }
            gate = HealthGate(version: version)
            use(b)
            log.info("activated rules version \(version)")
            reply(nil)
        }
    }

    private func health(_ outcome: Outcome, version: UInt64) {
        guard gate != nil, let decision = gate!.record(outcome, bundleVersion: version) else { return }
        gate = nil
        switch decision {
        case .healthy:
            do { try rules.markKnownGood() } catch { log.error("mark known-good: \(String(describing: error))") }
        case .rollback:
            rollback(reason: "rules version \(version) failed the local health gate")
        }
    }

    private func rollback(reason: String) {
        do {
            let good = try rules.rollback()
            guard let (_, bytes) = try rules.currentBundle() else { throw RulesStore.StoreError.notInstalled(good) }
            use(try RuleBundle(bytes: [UInt8](bytes), anchors: anchors, now: now(), mode: .load))
            alert("\(reason); rolled back to rules version \(good).")
        } catch {
            alert("\(reason); no known-good rules to roll back to (\(error)).")
        }
    }

    // MARK: pipeline

    private func offer(_ e: FileEvent) {
        debouncer.offer(e.key, payload: e.path, nowMs: nowMs())
        armDebounce()
    }

    private func armDebounce() {
        guard debounceTimer == nil, let wait = debouncer.nextDeadline(nowMs: nowMs()) else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(Int(wait)))
        t.setEventHandler { [unowned self] in
            debounceTimer = nil
            for (key, path) in debouncer.takeDue(nowMs: nowMs()) { enqueue(key, path) }
            armDebounce()
            pump()
        }
        debounceTimer = t
        t.resume()
    }

    private func enqueue(_ key: FileKey, _ path: String) {
        guard ready.count < Self.readyCapacity else {
            readyDropped += 1
            return
        }
        ready.append((key, path))
    }

    private func recoverJournal() {
        do {
            for j in try store.journalPending() {
                try store.journalRemove(j.id)
                enqueue(FileKey(dev: j.dev, ino: j.ino), j.path)
            }
        } catch {
            log.error("journal recovery: \(String(describing: error), privacy: .public)")
        }
    }

    private func pump() {
        while bundle != nil, inFlight < Self.maxInFlight, !ready.isEmpty {
            let (key, path) = ready.removeFirst()
            inspect(key, path)
        }
    }

    private func inspect(_ key: FileKey, _ path: String) {
        guard let bundle else { return }
        let format = bundle.format(forExtension: (path as NSString).pathExtension)
        let policy = bundle.policy(format: format)
        let c: Candidate
        do {
            c = try Candidate.open(key: key, path: path, maxBytes: policy.maxBytes)
        } catch Candidate.Skip.tooLarge {
            log.info("skipped file over the \(format, privacy: .public) size limit")
            return
        } catch {
            return // not a quarantined regular file any more, or gone
        }
        let version = bundle.info.version
        let cacheKey = VerdictCache.Key(sha256: c.sha256, bundleVersion: version)
        if let cached = cache.get(cacheKey) {
            record(c, outcome: cached, format: format, hits: [], detail: "cached verdict", bundle: bundle, telemetry: false)
            return
        }
        let journalID = try? store.journalAdd(dev: key.dev, ino: key.ino, path: path)
        inFlight += 1
        let job = InspectorPool.Job(fd: c.fd, size: c.size, formatHint: format == "other" ? nil : format,
                                    limits: policy.jobLimits)
        pool.inspect(job) { [unowned self] r in
            inFlight -= 1
            if c.unchangedSinceHash() { cache.put(cacheKey, r.outcome) }
            let detail = [r.stage1?.detail, r.stage2?.detail].compactMap { $0 }.filter { !$0.isEmpty }
                .joined(separator: "; ")
            record(c, outcome: r.outcome, format: r.stage1?.format ?? format, hits: r.stage1?.hits ?? [],
                   detail: detail, bundle: bundle, telemetry: true)
            if let journalID { try? store.journalRemove(journalID) }
            health(r.outcome, version: version)
            pump()
        }
    }

    /// Apply the bundle policy. The QUARANTINE action is reported like ALERT;
    /// moving files into a vault is not implemented (see docs/deploying.md#status).
    private func record(_ c: Candidate, outcome: Outcome, format: String, hits: [String], detail: String,
                        bundle: RuleBundle, telemetry: Bool) {
        let (severity, action) = bundle.action(for: outcome)
        let version = bundle.info.version
        do {
            if action.rawValue >= Action.log.rawValue {
                try store.addEvent(Store.Event(
                    path: c.path, sha256: c.shaHex, outcome: outcome, severity: severity.rawValue,
                    action: action.rawValue, bundleVersion: version, detail: detail, hits: hits,
                    quarantineAgent: c.quarantine.agent))
            }
            if telemetry {
                try store.spool(TelemetryRecord(
                    time: now(), sha256: c.shaHex, size: c.size, format: format, outcome: outcome,
                    severity: severity.rawValue, bundleVersion: version, quarantineAgent: c.quarantine.agent,
                    whereFroms: telemetryWhereFroms ? c.whereFroms.map { Data($0).base64EncodedString() } : nil,
                    hits: hits))
            }
        } catch {
            log.error("store: \(String(describing: error), privacy: .public)")
        }
        if action.rawValue >= Action.alert.rawValue {
            log.notice("\(outcome.name, privacy: .public) severity \(severity.rawValue) sha256 \(c.shaHex, privacy: .public)")
        }
    }

    private func alert(_ text: String) {
        log.error("\(text, privacy: .public)")
        _ = try? store.addSystemAlert(text, bundleVersion: bundle?.info.version ?? 0)
    }

    // MARK: XPC

    private func attach(_ role: PokeyConfig.Role, _ conn: xpc_connection_t) -> Bool {
        switch role {
        case .inspector: return pool.attach(conn)
        case .netd: return true
        case .ui: return isConsoleUser(conn)
        default: return false
        }
    }

    private func isConsoleUser(_ conn: xpc_connection_t) -> Bool {
        guard let uid = PeerIdentity.consoleUID() else { return false }
        return xpc_connection_get_euid(conn) == uid
    }

    private func handle(_ role: PokeyConfig.Role, _ conn: xpc_connection_t, _ msg: xpc_object_t) {
        do {
            switch role {
            case .inspector:
                pool.receive(msg, on: conn)
            case .netd:
                try handleNetd(conn, msg)
            case .ui:
                guard isConsoleUser(conn) else { throw ProtocolError("not the console user") }
                try handleUI(conn, msg)
            default:
                throw ProtocolError("unexpected role")
            }
        } catch {
            log.error("\(role.rawValue, privacy: .public) protocol error: \(String(describing: error), privacy: .public)")
            xpc_connection_cancel(conn)
        }
    }

    private func send(_ conn: xpc_connection_t, replyTo msg: xpc_object_t, _ fields: [String: Value]) throws {
        guard let r = XPCValue.reply(to: msg, fields) else { throw ProtocolError("message expects no reply") }
        xpc_connection_send_message(conn, r)
    }

    private func handleNetd(_ conn: xpc_connection_t, _ msg: xpc_object_t) throws {
        let m = try NetdMessage.parse(XPCValue.decode(msg, maxData: NetdMessage.maxBundleBytes))
        switch m {
        case .bundle(let bytes):
            guard xpc_dictionary_create_reply(msg) != nil else { throw ProtocolError("bundle expects a reply") }
            activate(bytes) { [unowned self] error in
                try? send(conn, replyTo: msg, ["ok": .bool(error == nil), "error": .string((error ?? "").truncated(toUTF8: 512))])
            }
        case .telemetryPull(let max):
            let t = try store.telemetry(max: max)
            try send(conn, replyTo: msg, ["up_to": .uint(UInt64(t?.upTo ?? 0)), "data": .data(t?.json ?? Array("[]".utf8))])
        case .telemetryAck(let upTo):
            try store.telemetryAck(upTo: upTo)
            try send(conn, replyTo: msg, ["ok": .bool(true)])
        }
    }

    private func handleUI(_ conn: xpc_connection_t, _ msg: xpc_object_t) throws {
        switch try UICommand.parse(XPCValue.decode(msg)) {
        case .status:
            let stats = es?.stats ?? (dropped: 0, lost: 0)
            try send(conn, replyTo: msg, [
                "rules_version": .uint(bundle?.info.version ?? 0),
                "rules_expired": .bool(bundle.map { now() >= $0.info.expires } ?? false),
                "open_alerts": .uint(UInt64(try store.openAlertCount())),
                "dropped": .uint(stats.dropped &+ readyDropped &+ debouncer.dropped),
                "lost": .uint(stats.lost),
            ])
        case .listAlerts(let limit):
            try send(conn, replyTo: msg, ["alerts": .array(try store.openAlerts(limit: limit))])
        case .ackAlert(let id):
            try store.ack(id)
            try send(conn, replyTo: msg, ["ok": .bool(true)])
        }
    }

    private func now() -> Int64 { Int64(Date().timeIntervalSince1970) }
    private func nowMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }
}
