import PKCS11RS
import UIKit

private let connectorURLKey = "PKCS11RSConnectorURL"
private let fallbackConnectorURL = "http://192.168.1.169:12345"

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

private func inspectModule(configuration: ConnectorConfiguration) -> String {
    var arguments = CK_C_INITIALIZE_ARGS()
    arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
    let initialize = configuration.json.withCString { json in
        arguments.pReserved = UnsafeMutableRawPointer(mutating: json)
        return C_Initialize(&arguments)
    }
    guard initialize == CKR_OK else {
        return "C_Initialize failed: \(initialize)"
    }
    defer { C_Finalize(nil) }

    var info = CK_INFO()
    let getInfo = C_GetInfo(&info)
    guard getInfo == CKR_OK else {
        return "C_GetInfo failed: \(getInfo)"
    }

    var count: CK_ULONG = 0
    let countResult = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count)
    guard countResult == CKR_OK else {
        return "C_GetSlotList(count) failed: \(countResult)"
    }

    var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
    let listResult = slots.withUnsafeMutableBufferPointer { buffer in
        C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
    }
    guard listResult == CKR_OK else {
        return "C_GetSlotList(list) failed: \(listResult)"
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
    }

    return lines.joined(separator: "\n")
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var textView: UITextView?
    private let inspectionQueue = DispatchQueue(
        label: "com.qpernil.PKCS11RSSmoke.inspection",
        qos: .userInitiated
    )

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

    private func refresh() {
        let configuration = connectorConfiguration()
        textView?.text = "Connecting to YubiHSM at\n\(configuration.url)…"
        inspectionQueue.async { [weak self] in
            let result = inspectModule(configuration: configuration)
            print(result)
            DispatchQueue.main.async {
                self?.textView?.text = result
            }
        }
    }
}
