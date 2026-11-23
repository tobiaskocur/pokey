import EDRPlatform
import Foundation

// System extension entry point: root, Endpoint Security, no network.
let sensor: Sensor
do {
    sensor = try Sensor(config: EDRConfig.main())
    try sensor.start()
} catch {
    logger("main").fault("edr-sensor failed to start: \(String(describing: error), privacy: .public)")
    exit(1)
}
dispatchMain()
