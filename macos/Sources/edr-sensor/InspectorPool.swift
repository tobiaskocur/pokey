import EDRCore
import EDRPlatform
import Foundation
import XPC

/// Spawns and supervises inspector processes. One job per process; one
/// pre-warmed worker is kept ready. All state lives on `queue`.
///
/// Lifecycle: pipe + one-time nonce -> posix_spawn (fd 3 = nonce pipe) ->
/// inspector connects to the sensor Mach service -> XPCServer hands the
/// connection here if the peer satisfies the inspector requirement -> PID must
/// be one we spawned, nonce must match -> init (rules fd) -> ready -> job ->
/// stage1 [-> stage2] -> exit. The watchdog (deadline, footprint) runs from
/// job send to exit; waitpid gives the exit status.
final class InspectorPool {
    struct Result {
        var outcome: Outcome
        var stage1: Stage1Reply?
        var stage2: Stage2Reply?
    }

    struct Rules {
        var path: URL
        var anchors: [[UInt8]]
        var threshold: Int
        var memoryLimitMB: UInt32
    }

    private final class Worker {
        let pid: pid_t
        var session: InspectorSession
        var connection: xpc_connection_t?
        var protocolError = false
        var watchdog: Watchdog?
        var timer: DispatchSourceTimer?
        var exitSource: DispatchSourceProcess?
        var prewarmTimer: DispatchSourceTimer?
        let rules: Rules
        /// Set for a job worker; probes (activation self-test) use onReady.
        var onDone: ((Result) -> Void)?
        var onReady: ((Bool) -> Void)?

        init(pid: pid_t, nonce: [UInt8], rules: Rules) {
            self.pid = pid
            session = InspectorSession(nonce: nonce)
            self.rules = rules
        }
    }

    static let prewarmDeadlineMs = 20_000

    private let queue: DispatchQueue
    private let executable: String
    private let log = logger("inspector")
    private var workers: [pid_t: Worker] = [:]
    private var spare: Worker?
    private var waiting: [(job: Job, done: (Result) -> Void)] = []
    private var busy = false
    private var nextJobID: UInt64 = 1
    private var consecutiveSpawnFailures = 0
    var rules: Rules?

    struct Job {
        var fd: Int32
        var size: UInt64
        var formatHint: String?
        var limits: JobLimits
    }

    init(queue: DispatchQueue, executable: String) {
        self.queue = queue
        self.executable = executable
    }

    // MARK: public (call on queue)

    /// Keep one worker pre-warmed with the current rules.
    func ensureSpare() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard spare == nil, let rules, consecutiveSpawnFailures < 5 else { return }
        spare = spawn(rules: rules)
    }

    /// Discard the spare (rules changed) and pre-warm a new one.
    func rulesChanged(_ new: Rules) {
        rules = new
        if let s = spare { kill(s.pid, SIGKILL) }
        spare = nil
        consecutiveSpawnFailures = 0
        ensureSpare()
    }

    func inspect(_ job: Job, done: @escaping (Result) -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        waiting.append((job, done))
        pump()
    }

    /// Activation self-test: a fresh inspector with `rules` reaches READY only
    /// after the bundle loads, YARA compiles and every self-test vector passes.
    func probe(rules: Rules, done: @escaping (Bool) -> Void) {
        guard let w = spawn(rules: rules) else { return done(false) }
        w.onReady = done
    }

    /// XPCServer calls this for the first message of a connection whose peer
    /// satisfies the inspector code-signing requirement.
    func accept(_ conn: xpc_connection_t, first: xpc_object_t) {
        let pid = xpc_connection_get_pid(conn)
        guard let w = workers[pid], w.connection == nil else {
            log.error("inspector connection from unknown pid \(pid)")
            xpc_connection_cancel(conn)
            return
        }
        w.connection = conn
        xpc_connection_set_target_queue(conn, queue)
        xpc_connection_set_event_handler(conn) { [weak self, weak w] msg in
            guard let self, let w else { return }
            if xpc_get_type(msg) == XPC_TYPE_DICTIONARY { self.receive(msg, from: w) }
        }
        xpc_connection_activate(conn)
        receive(first, from: w)
    }

    // MARK: internals

    private func pump() {
        guard !busy, !waiting.isEmpty else { return }
        guard let w = spare, w.session.state == .ready else {
            ensureSpare()
            if spare == nil {
                // Cannot spawn (missing user, repeated failures): fail closed.
                let (_, done) = waiting.removeFirst()
                done(Result(outcome: .crash))
                pump()
            }
            return
        }
        spare = nil
        busy = true
        let (job, done) = waiting.removeFirst()
        w.onDone = { [weak self] r in
            done(r)
            self?.busy = false
            self?.ensureSpare()
            self?.pump()
        }
        send(job, to: w)
        ensureSpare()
    }

    private func send(_ job: Job, to w: Worker) {
        let id = nextJobID
        nextJobID += 1
        do { try w.session.sentJob(id: id, decode: job.limits.decode) } catch { return fail(w) }
        var d: [String: Value] = ["type": .string("job"), "job_id": .uint(id), "size": .uint(job.size),
                                  "limits": job.limits.value]
        if let h = job.formatHint { d["format_hint"] = .string(h) }
        let msg = XPCValue.encode(.dict(d))
        xpc_dictionary_set_fd(msg, "file_fd", job.fd)
        let now = Self.nowMs()
        w.watchdog = Watchdog(startMs: now, deadlineMs: UInt64(job.limits.deadlineMs),
                              maxFootprint: UInt64(w.rules.memoryLimitMB) << 20)
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .milliseconds(Int(Watchdog.pollIntervalMs)))
        t.setEventHandler { [weak self, weak w] in
            guard let self, let w, w.watchdog != nil else { return }
            if w.watchdog!.check(nowMs: Self.nowMs(), footprint: Self.footprint(w.pid)) != nil {
                kill(w.pid, SIGKILL)
                self.log.info("watchdog killed inspector \(w.pid)")
            }
        }
        w.timer = t
        t.resume()
        if let c = w.connection { xpc_connection_send_message(c, msg) }
    }

    private func spawn(rules: Rules) -> Worker? {
        var nonce = [UInt8](repeating: 0, count: InspectorProtocol.nonceLength)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else { return nil }
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return nil }
        defer { close(fds[0]) }

        var fa: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fa)
        defer { posix_spawn_file_actions_destroy(&fa) }
        posix_spawn_file_actions_adddup2(&fa, fds[0], InspectorProtocol.nonceFD)
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        // Only the descriptors named above are inherited.
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))

        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [strdup(executable), nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        defer { argv.forEach { free($0) } }
        let rc = posix_spawn(&pid, executable, &fa, &attr, argv, envp)
        guard rc == 0 else {
            close(fds[1])
            consecutiveSpawnFailures += 1
            log.error("posix_spawn inspector failed: \(rc)")
            return nil
        }
        let written = write(fds[1], nonce, nonce.count)
        close(fds[1])
        let w = Worker(pid: pid, nonce: nonce, rules: rules)
        workers[pid] = w
        guard written == nonce.count else {
            fail(w)
            return w
        }

        let src = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: queue)
        src.setEventHandler { [weak self, weak w] in
            guard let self, let w else { return }
            self.reaped(w)
        }
        w.exitSource = src
        src.resume()

        let pt = DispatchSource.makeTimerSource(queue: queue)
        pt.schedule(deadline: .now() + .milliseconds(Self.prewarmDeadlineMs))
        pt.setEventHandler { [weak w] in
            guard let w, w.session.state != .ready, w.session.jobID == nil else { return }
            kill(w.pid, SIGKILL)
        }
        w.prewarmTimer = pt
        pt.resume()
        return w
    }

    private func receive(_ msg: xpc_object_t, from w: Worker) {
        do {
            let parsed = try InspectorMessage.parse(XPCValue.decode(msg))
            let before = w.session.state
            try w.session.receive(parsed)
            if before == .awaitingHello { try sendInit(to: w) }
            if w.session.state == .ready {
                w.prewarmTimer?.cancel()
                consecutiveSpawnFailures = 0
                if let probe = w.onReady {
                    w.onReady = nil
                    probe(true)
                    kill(w.pid, SIGKILL)
                } else {
                    pump()
                }
            }
        } catch {
            log.error("inspector \(w.pid) protocol violation: \(String(describing: error))")
            fail(w)
        }
    }

    private func sendInit(to w: Worker) throws {
        let fd = open(w.rules.path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ProtocolError("cannot open rules") }
        defer { close(fd) }
        let msg = XPCValue.encode(.dict([
            "type": .string("init"), "roots": .array(w.rules.anchors.map { .data($0) }),
            "threshold": .uint(UInt64(w.rules.threshold)), "now": .int(Int64(Date().timeIntervalSince1970)),
        ]))
        xpc_dictionary_set_fd(msg, "rules_fd", fd)
        if let c = w.connection { xpc_connection_send_message(c, msg) }
    }

    private func fail(_ w: Worker) {
        w.protocolError = true
        kill(w.pid, SIGKILL)
    }

    private func reaped(_ w: Worker) {
        var status: Int32 = 0
        guard waitpid(w.pid, &status, WNOHANG) == w.pid else { return }
        w.timer?.cancel()
        w.prewarmTimer?.cancel()
        w.exitSource?.cancel()
        if let c = w.connection { xpc_connection_cancel(c) }
        workers[w.pid] = nil
        let sig = status & 0x7f
        let exit: ExitStatus = sig == 0 ? .exited((status >> 8) & 0xff) : .signaled(sig)

        if let probe = w.onReady {
            w.onReady = nil
            probe(false)
            return
        }
        if spare === w {
            spare = nil
            consecutiveSpawnFailures += 1
            log.error("pre-warmed inspector \(w.pid) died before READY: \(String(describing: exit))")
            if consecutiveSpawnFailures < 5 {
                queue.asyncAfter(deadline: .now() + .seconds(consecutiveSpawnFailures)) { [weak self] in
                    self?.ensureSpare()
                    self?.pump()
                }
            } else {
                pump() // fails waiting jobs closed
            }
            return
        }
        guard let done = w.onDone else { return }
        w.onDone = nil
        let outcome = Verdict.resolve(session: w.session, protocolError: w.protocolError,
                                      killReason: w.watchdog?.killReason, exit: exit)
        done(Result(outcome: outcome, stage1: w.session.stage1, stage2: w.session.stage2))
    }

    private static func nowMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }

    private static func footprint(_ pid: pid_t) -> UInt64 {
        var info = rusage_info_v4()
        let rc = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
        }
        return rc == 0 ? info.ri_phys_footprint : 0
    }
}
