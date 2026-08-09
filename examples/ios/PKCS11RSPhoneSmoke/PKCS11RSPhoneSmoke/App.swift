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
        "logging": [
            "level": "debug",
        ],
        "yubihsm": [
            "urls": [url],
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

private final class LogBuffer {
    private let lock = NSLock()
    private var observer: (([String]) -> Void)?
    private var pendingLines = [String]()
    private var deliveryScheduled = false

    func observe(_ observer: @escaping ([String]) -> Void) {
        lock.lock()
        self.observer = observer
        lock.unlock()
    }

    func append(_ line: String) {
        lock.lock()
        pendingLines.append(line)
        let shouldSchedule = !deliveryScheduled
        deliveryScheduled = true
        lock.unlock()
        if shouldSchedule {
            DispatchQueue.main.async { [weak self] in
                self?.deliver()
            }
        }
    }

    private func deliver() {
        lock.lock()
        let lines = pendingLines
        pendingLines.removeAll(keepingCapacity: true)
        deliveryScheduled = false
        let observer = observer
        lock.unlock()
        if !lines.isEmpty {
            observer?(lines)
        }
    }
}

private let logEventCallback: PKCS11RS_LOG_EVENT = {
    context,
    _,
    _,
    _,
    message,
    messageLength in
    guard let context else { return }
    let count = Int(messageLength)
    guard count == 0 || message != nil else { return }
    let line = count == 0
        ? ""
        : String(decoding: UnsafeBufferPointer(start: message, count: count), as: UTF8.self)
    Unmanaged<LogBuffer>.fromOpaque(context).takeUnretainedValue().append(line)
}

private final class InspectionViewController: UIViewController {
    private let selector = UISegmentedControl(items: ["Log", "Inventory"])
    private let statusLabel = UILabel()
    private let inventoryView = UITextView()
    private let logView = UITextView()
    private var refreshStartedAt: Date?
    private var refreshTimer: Timer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        selector.selectedSegmentIndex = 0
        selector.addTarget(self, action: #selector(selectionChanged), for: .valueChanged)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        statusLabel.textColor = .secondaryLabel
        statusLabel.isHidden = true
        view.addSubview(statusLabel)

        for textView in [inventoryView, logView] {
            textView.translatesAutoresizingMaskIntoConstraints = false
            textView.backgroundColor = .systemBackground
            textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
            textView.isEditable = false
            textView.textContainerInset = UIEdgeInsets(top: 8, left: 12, bottom: 20, right: 12)
            view.addSubview(textView)
        }
        selector.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(selector)
        NSLayoutConstraint.activate([
            selector.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            selector.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            selector.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor, multiplier: 0.8),
            statusLabel.topAnchor.constraint(equalTo: selector.bottomAnchor, constant: 6),
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            inventoryView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 4),
            inventoryView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            inventoryView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            inventoryView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            logView.topAnchor.constraint(equalTo: inventoryView.topAnchor),
            logView.leadingAnchor.constraint(equalTo: inventoryView.leadingAnchor),
            logView.trailingAnchor.constraint(equalTo: inventoryView.trailingAnchor),
            logView.bottomAnchor.constraint(equalTo: inventoryView.bottomAnchor),
        ])
        selectionChanged()
    }

    func beginRefresh(connector: String) {
        appendLogs(["\n—— Refresh: \(connector) ——"])
        selector.selectedSegmentIndex = 0
        selectionChanged()
        refreshTimer?.invalidate()
        refreshStartedAt = Date()
        updateRefreshStatus()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) {
            [weak self] _ in
            self?.updateRefreshStatus()
        }
    }

    func appendLogs(_ lines: [String]) {
        guard !lines.isEmpty else { return }
        let separator = logView.textStorage.length == 0 ? "" : "\n"
        let text = separator + lines.joined(separator: "\n")
        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.paragraphSpacing = 8
        logView.textStorage.append(NSAttributedString(
            string: text,
            attributes: [
                .font: logView.font as Any,
                .foregroundColor: UIColor.label,
                .paragraphStyle: paragraphStyle,
            ]
        ))
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let length = self.logView.textStorage.length
            guard length > 0 else { return }
            self.logView.layoutManager.ensureLayout(for: self.logView.textContainer)
            self.logView.scrollRangeToVisible(NSRange(location: length - 1, length: 1))
        }
    }

    func showInventory(_ inventory: String) {
        refreshTimer?.invalidate()
        refreshTimer = nil
        refreshStartedAt = nil
        statusLabel.isHidden = true
        inventoryView.text = inventory
    }

    private func updateRefreshStatus() {
        guard let refreshStartedAt else { return }
        let seconds = max(0, Int(Date().timeIntervalSince(refreshStartedAt)))
        statusLabel.text = "Working… \(seconds)s"
        statusLabel.isHidden = false
    }

    @objc private func selectionChanged() {
        let showsInventory = selector.selectedSegmentIndex == 1
        inventoryView.isHidden = !showsInventory
        logView.isHidden = showsInventory
    }
}

private final class ModuleInspector {
    private var initialized = false

    func inspect(
        configuration: ConnectorConfiguration,
        smartCardDiscovery: SmartCardReaderDiscovery,
        logBuffer: LogBuffer
    ) -> String {
        if !initialized {
            var arguments = CK_C_INITIALIZE_ARGS()
            arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
            var extensionArguments = PKCS11RS_INITIALIZE_ARGS_V1()
            extensionArguments.ulMagic = CK_ULONG(PKCS11RS_INITIALIZE_ARGS_MAGIC)
            extensionArguments.ulSize = CK_ULONG(
                MemoryLayout<PKCS11RS_INITIALIZE_ARGS_V1>.size
            )
            extensionArguments.ulVersion = CK_ULONG(PKCS11RS_INITIALIZE_ARGS_VERSION)
            extensionArguments.ulConfigurationLen = CK_ULONG(configuration.json.utf8.count)
            extensionArguments.pHardwareContext = Unmanaged
                .passUnretained(smartCardDiscovery)
                .toOpaque()
            extensionArguments.enumerateCcidReaders = enumerateCcidReadersCallback
            extensionArguments.pLogContext = Unmanaged.passUnretained(logBuffer).toOpaque()
            extensionArguments.logEvent = logEventCallback
            let initialize = configuration.json.withCString { json in
                extensionArguments.pConfiguration = UnsafeRawPointer(json)
                    .assumingMemoryBound(to: CK_UTF8CHAR.self)
                return withUnsafeMutablePointer(to: &extensionArguments) { extensionPointer in
                    arguments.pReserved = UnsafeMutableRawPointer(extensionPointer)
                    return C_Initialize(&arguments)
                }
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
    private let controller = InspectionViewController()
    private let logBuffer = LogBuffer()
    private let inspectionQueue = DispatchQueue(
        label: "com.qpernil.PKCS11RSSmoke.inspection",
        qos: .userInitiated
    )
    private let moduleInspector = ModuleInspector()
    private let smartCardDiscovery = SmartCardReaderDiscovery()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        logBuffer.observe { [weak controller] lines in
            controller?.appendLogs(lines)
        }

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
        controller.beginRefresh(connector: configuration.url)
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = moduleInspector.inspect(
                configuration: configuration,
                smartCardDiscovery: smartCardDiscovery,
                logBuffer: logBuffer
            )
            DispatchQueue.main.async {
                self.controller.showInventory(result)
            }
        }
    }
}
