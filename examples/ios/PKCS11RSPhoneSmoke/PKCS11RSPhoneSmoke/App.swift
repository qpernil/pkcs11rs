import PKCS11RS
import UIKit

private let connectorURLKey = "PKCS11RSConnectorURL"
private let fallbackConnectorURL = "http://192.168.1.169:12345"
private let initialSlotListCapacity = 10
private let initialMechanismListCapacity = 100

private struct ConnectorConfiguration {
    let url: String
    let json: String
}

private func connectorConfiguration() -> ConnectorConfiguration {
    let environment = ProcessInfo.processInfo.environment
    let defaults = UserDefaults.standard
    let url = environment["PKCS11RS_YUBIHSM_URLS"]
        ?? defaults.string(forKey: connectorURLKey)
        ?? fallbackConnectorURL
    defaults.set(url, forKey: connectorURLKey)

    let object: [String: Any] = [
        "version": 1,
        "hardware": [
            "discovery": false,
        ],
        "yubihsm": [
            "urls": [url],
            "usb": false,
        ],
    ]
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return ConnectorConfiguration(
        url: url,
        json: String(decoding: data, as: UTF8.self)
    )
}

private func paddedString<T>(_ value: T) -> String {
    withUnsafeBytes(of: value) { bytes in
        String(decoding: bytes, as: UTF8.self)
            .trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
    }
}

private func mechanismName(_ mechanism: CK_MECHANISM_TYPE) -> String {
    if let name = PKCS11RS_GetMechanismName(mechanism) {
        return String(cString: name)
    }
    return String(format: "Unknown mechanism 0x%08llX", UInt64(mechanism))
}

private final class ModuleInspector {
    private var initialized = false

    func inspect(configuration: ConnectorConfiguration) -> String {
        if !initialized {
            var arguments = CK_C_INITIALIZE_ARGS()
            arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
            let initialize = configuration.json.withCString { json in
                arguments.pReserved = UnsafeMutableRawPointer(mutating: json)
                return C_Initialize(&arguments)
            }
            guard initialize == CKR_OK else {
                return "C_Initialize failed: \(initialize)"
            }
            initialized = true
        }

        var info = CK_INFO()
        let getInfo = C_GetInfo(&info)
        guard getInfo == CKR_OK else {
            return "C_GetInfo failed: \(getInfo)"
        }

        var count = CK_ULONG(initialSlotListCapacity)
        var slots = [CK_SLOT_ID](repeating: 0, count: initialSlotListCapacity)
        var listResult = slots.withUnsafeMutableBufferPointer { buffer in
            C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
        }
        while listResult == CKR_BUFFER_TOO_SMALL && Int(count) > slots.count {
            slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
            listResult = slots.withUnsafeMutableBufferPointer { buffer in
                C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
            }
        }
        guard listResult == CKR_OK else {
            return "C_GetSlotList failed: \(listResult)"
        }

        var lines = [
            "PKCS11RS on iPhone",
            "",
            "Cryptoki: \(info.cryptokiVersion.major).\(info.cryptokiVersion.minor)",
            "Manufacturer: \(paddedString(info.manufacturerID))",
            "Library: \(paddedString(info.libraryDescription)) \(info.libraryVersion.major).\(info.libraryVersion.minor)",
            "Configuration: C_Initialize JSON",
            "Connector: \(configuration.url)",
            "",
            "Token-present slots: \(count)",
        ]

        for slot in slots.prefix(Int(count)) {
            var slotInfo = CK_SLOT_INFO()
            var tokenInfo = CK_TOKEN_INFO()
            let slotResult = C_GetSlotInfo(slot, &slotInfo)
            let tokenResult = C_GetTokenInfo(slot, &tokenInfo)
            guard slotResult == CKR_OK, tokenResult == CKR_OK else {
                lines.append("Slot \(slot) query failed: \(slotResult)/\(tokenResult)")
                continue
            }
            lines.append("")
            lines.append("Slot \(slot): \(paddedString(slotInfo.slotDescription))")
            lines.append("Token: \(paddedString(tokenInfo.label))")
            lines.append("Serial: \(paddedString(tokenInfo.serialNumber))")

            var mechanismCount = CK_ULONG(initialMechanismListCapacity)
            var mechanisms = [CK_MECHANISM_TYPE](
                repeating: 0,
                count: initialMechanismListCapacity
            )
            var mechanismListResult = mechanisms.withUnsafeMutableBufferPointer { buffer in
                C_GetMechanismList(slot, buffer.baseAddress, &mechanismCount)
            }
            while mechanismListResult == CKR_BUFFER_TOO_SMALL
                && Int(mechanismCount) > mechanisms.count
            {
                mechanisms = [CK_MECHANISM_TYPE](
                    repeating: 0,
                    count: Int(mechanismCount)
                )
                mechanismListResult = mechanisms.withUnsafeMutableBufferPointer { buffer in
                    C_GetMechanismList(slot, buffer.baseAddress, &mechanismCount)
                }
            }
            guard mechanismListResult == CKR_OK else {
                lines.append("C_GetMechanismList failed: \(mechanismListResult)")
                continue
            }

            lines.append("")
            lines.append("Mechanisms: \(mechanismCount)")
            for mechanism in mechanisms.prefix(Int(mechanismCount)) {
                var mechanismInfo = CK_MECHANISM_INFO()
                let mechanismResult = C_GetMechanismInfo(
                    slot,
                    mechanism,
                    &mechanismInfo
                )
                let name = mechanismName(mechanism)
                guard mechanismResult == CKR_OK else {
                    lines.append("  \(name): C_GetMechanismInfo failed: \(mechanismResult)")
                    continue
                }
                let flags = String(format: "0x%08llX", UInt64(mechanismInfo.flags))
                lines.append(
                    "  \(name): keys \(mechanismInfo.ulMinKeySize)-\(mechanismInfo.ulMaxKeySize), flags \(flags)"
                )
            }
        }

        return lines.joined(separator: "\n")
    }

    func finalize() {
        if initialized {
            let result = C_Finalize(nil)
            if result == CKR_OK {
                initialized = false
            } else {
                print("C_Finalize failed: \(result)")
            }
        }
    }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var textView: UITextView?
    private let inspectionQueue = DispatchQueue(
        label: "com.qpernil.PKCS11RSSmoke.inspection",
        qos: .userInitiated
    )
    private let moduleInspector = ModuleInspector()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let textView = UITextView()
        textView.backgroundColor = .systemBackground
        textView.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        textView.isEditable = false
        textView.textContainerInset = UIEdgeInsets(top: 64, left: 20, bottom: 20, right: 20)

        let controller = UIViewController()
        controller.view = textView
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        self.textView = textView

        return true
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        refresh()
    }

    func applicationWillTerminate(_ application: UIApplication) {
        inspectionQueue.sync {
            moduleInspector.finalize()
        }
    }

    private func refresh() {
        let configuration = connectorConfiguration()
        textView?.text = "Connecting to YubiHSM at\n\(configuration.url)…"
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = moduleInspector.inspect(configuration: configuration)
            print(result)
            DispatchQueue.main.async {
                self.textView?.text = result
            }
        }
    }
}
