/// Sensor-side watchdog decisions for one inspector process. The macOS layer
/// polls `proc_pid_rusage(RUSAGE_INFO_V4).ri_phys_footprint` every
/// `pollIntervalMs`, sends SIGKILL when `check` returns a reason, and reaps the
/// child with `waitpid`; `Verdict.resolve` turns that into an outcome.
public struct Watchdog: Sendable {
    public enum KillReason: Equatable, Sendable { case deadline, footprint }

    public static let pollIntervalMs: UInt64 = 25

    public let startMs: UInt64
    public let deadlineMs: UInt64
    public let maxFootprint: UInt64
    public private(set) var killReason: KillReason?

    public init(startMs: UInt64, deadlineMs: UInt64, maxFootprint: UInt64) {
        self.startMs = startMs
        self.deadlineMs = deadlineMs
        self.maxFootprint = maxFootprint
    }

    /// Returns the reason to kill now, once; later calls return nil.
    public mutating func check(nowMs: UInt64, footprint: UInt64) -> KillReason? {
        guard killReason == nil else { return nil }
        if footprint > maxFootprint {
            killReason = .footprint
        } else if nowMs &- startMs >= deadlineMs {
            killReason = .deadline
        }
        return killReason
    }
}

/// How the inspector process ended (from waitpid).
public enum ExitStatus: Equatable, Sendable {
    case exited(Int32)
    case signaled(Int32)
}

public enum Verdict {
    /// Final outcome of one inspection.
    ///
    /// - A protocol error at any point is PROTOCOL_VIOLATION.
    /// - Our own kill is TIMEOUT (deadline) or RESOURCE_EXCEEDED (footprint).
    /// - Any other signal is CRASH.
    /// - A normal exit before the session finished is PROTOCOL_VIOLATION.
    /// Stage 1 results already received are kept and combined, so a decoder
    /// crash after a static match still reports the match's severity or worse.
    public static func resolve(session: InspectorSession, protocolError: Bool, killReason: Watchdog.KillReason?,
                               exit: ExitStatus) -> Outcome {
        let reported = session.stage1.map { s1 in
            session.stage2.map { s1.outcome.combined(with: $0.outcome) } ?? s1.outcome
        }
        let failure: Outcome?
        if protocolError {
            failure = .protocolViolation
        } else if let killReason {
            failure = killReason == .deadline ? .timeout : .resourceExceeded
        } else if case .signaled = exit {
            failure = .crash
        } else if session.state != .done {
            failure = .protocolViolation
        } else {
            failure = nil
        }
        switch (reported, failure) {
        case (let r?, let f?): return r.combined(with: f)
        case (let r?, nil): return r
        case (nil, let f?): return f
        case (nil, nil): return .protocolViolation
        }
    }
}
