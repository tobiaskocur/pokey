import AppKit
import EDRCore
import EDRPlatform
import Foundation
import UserNotifications

// edr-ui: per-user LaunchAgent (SMAppService.agent) packaged as a background
// app so it can post notifications. It polls the sensor's allowlisted UI
// commands, shows each new alert once, and acknowledges an alert when the user
// picks "Acknowledge". It never reads files or parses file contents.

let log = logger("ui")

struct Alert {
    let id: UInt64
    let path: String
    let outcome: String
    let severity: UInt64
    let detail: String

    init(_ v: Value) throws {
        let f = try Fields(v, required: ["id", "time", "path", "outcome", "severity", "detail"])
        id = try f.uint("id")
        path = try f.string("path")
        outcome = try f.string("outcome")
        severity = try f.uint("severity", max: 255)
        detail = try f.string("detail")
    }
}

final class Agent: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    static let category = "edr.alert"
    static let ackAction = "edr.ack"

    private let client: SensorClient
    private let queue = DispatchQueue(label: "edr.ui.poll")
    private var shown = Set<UInt64>()
    private var timer: DispatchSourceTimer?

    init(config: EDRConfig) {
        client = SensorClient(config: config)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let ack = UNNotificationAction(identifier: Self.ackAction, title: "Acknowledge", options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.category, actions: [ack], intentIdentifiers: [], options: []),
        ])
        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if !granted { log.notice("notifications not authorized: \(String(describing: error), privacy: .public)") }
        }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .seconds(10), leeway: .seconds(2))
        t.setEventHandler { [weak self] in self?.poll() }
        t.resume()
        timer = t
    }

    private func poll() {
        do {
            let status = try Fields(client.request(UICommand.status.value),
                                    required: ["rules_version", "rules_expired", "open_alerts", "dropped", "lost"])
            if try status.uint("open_alerts") > 0 {
                let reply = try Fields(client.request(UICommand.listAlerts(limit: UICommand.maxAlerts).value),
                                       required: ["alerts"])
                guard let list = reply.value("alerts")?.array else { throw ProtocolError("alerts: not an array") }
                let alerts = try list.map(Alert.init)
                for a in alerts where !shown.contains(a.id) {
                    shown.insert(a.id)
                    notify(a)
                }
                // Forget acknowledged ones so the set stays bounded.
                shown.formIntersection(alerts.map(\.id))
            } else {
                shown.removeAll()
            }
        } catch {
            log.error("poll failed: \(String(describing: error), privacy: .public)")
        }
    }

    private func notify(_ a: Alert) {
        let content = UNMutableNotificationContent()
        content.title = a.path.isEmpty ? "Endpoint alert" : "Suspicious file"
        content.subtitle = a.path
        content.body = a.detail.isEmpty ? a.outcome : "\(a.outcome): \(a.detail)"
        content.categoryIdentifier = Self.category
        content.userInfo = ["id": String(a.id)]
        content.sound = a.severity >= 3 ? .default : nil
        let req = UNNotificationRequest(identifier: "edr.alert.\(a.id)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { error in
            if let error { log.error("notification failed: \(error.localizedDescription, privacy: .public)") }
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        guard response.actionIdentifier == Self.ackAction,
              let s = response.notification.request.content.userInfo["id"] as? String, let id = UInt64(s)
        else { return done() }
        queue.async { [client] in
            do {
                _ = try Fields(client.request(UICommand.ackAlert(id: id).value), required: ["ok"])
            } catch {
                log.error("ack failed: \(String(describing: error), privacy: .public)")
            }
            DispatchQueue.main.async(execute: done)
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list, .sound])
    }
}

let agent: Agent
do {
    agent = Agent(config: try EDRConfig.main())
} catch {
    log.fault("edr-ui failed to start: \(String(describing: error), privacy: .public)")
    exit(1)
}
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = agent
app.run()
