import PokeyPlatform
import Foundation

// System extension entry point: root, Endpoint Security, no network.
let sensor: Sensor
do {
    sensor = try Sensor(config: PokeyConfig.main())
    try sensor.start()
} catch {
    logger("main").fault("pokey-sensor failed to start: \(String(describing: error), privacy: .public)")
    exit(1)
}
dispatchMain()
