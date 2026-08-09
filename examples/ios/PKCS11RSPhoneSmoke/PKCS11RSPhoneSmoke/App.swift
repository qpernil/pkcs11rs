import PKCS11RS
import UIKit

private let connectorURLKey = "PKCS11RSConnectorURL"
private let fallbackConnectorURL = "http://192.168.1.169:12345"
private let initialSlotListCapacity = 10
private let objectFindBatchCapacity = 64
private let objectAttributeBufferCapacity = 1024
private let yubiHsmAuthenticationKeyID = "1234"
private let yubiHsmAuthPassword = "password"
private let ckaYubicoHsmAuthAlgorithm =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5901)
private let ckaYubicoHsmAuthRetries =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5902)
private let ckaYubicoHsmAuthTouchRequired =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5903)

private struct HsmAuthCredential {
    let label: String
    let source: String
    let algorithm: CK_ULONG
    let retries: CK_ULONG
    let touchRequired: Bool

    var username: String {
        ":\(yubiHsmAuthenticationKeyID)\(label)@\(source)"
    }

    var algorithmName: String {
        switch algorithm {
        case 38:
            return "symmetric AES-128"
        case 39:
            return "asymmetric P-256"
        default:
            return "algorithm \(algorithm)"
        }
    }

    var description: String {
        "\(label.debugDescription) @ \(source), \(algorithmName), retries \(retries), touch \(touchRequired ? "required" : "not required")"
    }
}

private struct ObjectInspection {
    let description: String
    let credential: HsmAuthCredential?
}

private struct ObjectInventory {
    var lines: [String]
    let credentials: [HsmAuthCredential]
}

private struct SlotInventory {
    let slot: CK_SLOT_ID
    let description: String
    let tokenLabel: String
    let serial: String
    let objects: ObjectInventory
}

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
            "public_discovery": "0001password",
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

private func objectClassName(_ objectClass: CK_OBJECT_CLASS) -> String {
    if let name = PKCS11RS_GetObjectClassName(objectClass) {
        return String(cString: name)
    }
    return String(format: "Unknown class 0x%08llX", UInt64(objectClass))
}

private func keyTypeName(_ keyType: CK_KEY_TYPE) -> String {
    if let name = PKCS11RS_GetKeyTypeName(keyType) {
        return String(cString: name)
    }
    return String(format: "Unknown key type 0x%08llX", UInt64(keyType))
}

private func availableLength(_ attribute: CK_ATTRIBUTE, capacity: Int) -> Int? {
    guard attribute.ulValueLen != CK_ULONG(CK_UNAVAILABLE_INFORMATION),
          attribute.ulValueLen <= CK_ULONG(capacity)
    else {
        return nil
    }
    return Int(attribute.ulValueLen)
}

private func hexString(_ bytes: ArraySlice<UInt8>) -> String {
    bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
}

private func objectDescription(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    source: String?
) -> ObjectInspection {
    var objectClass = CK_OBJECT_CLASS()
    var keyType = CK_KEY_TYPE()
    var hsmAuthAlgorithm = CK_ULONG()
    var hsmAuthRetries = CK_ULONG()
    var hsmAuthTouchRequired = CK_BBOOL()
    var label = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var identifier = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var attributes = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 7)

    let result = withUnsafeMutablePointer(to: &objectClass) { objectClassPointer in
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
            withUnsafeMutablePointer(to: &hsmAuthAlgorithm) { algorithmPointer in
                withUnsafeMutablePointer(to: &hsmAuthRetries) { retriesPointer in
                    withUnsafeMutablePointer(to: &hsmAuthTouchRequired) { touchPointer in
                        label.withUnsafeMutableBytes { labelBuffer in
                            identifier.withUnsafeMutableBytes { identifierBuffer in
                                attributes[0].type = CK_ATTRIBUTE_TYPE(CKA_CLASS)
                                attributes[0].pValue = UnsafeMutableRawPointer(objectClassPointer)
                                attributes[0].ulValueLen = CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)
                                attributes[1].type = CK_ATTRIBUTE_TYPE(CKA_LABEL)
                                attributes[1].pValue = labelBuffer.baseAddress
                                attributes[1].ulValueLen = CK_ULONG(labelBuffer.count)
                                attributes[2].type = CK_ATTRIBUTE_TYPE(CKA_ID)
                                attributes[2].pValue = identifierBuffer.baseAddress
                                attributes[2].ulValueLen = CK_ULONG(identifierBuffer.count)
                                attributes[3].type = CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE)
                                attributes[3].pValue = UnsafeMutableRawPointer(keyTypePointer)
                                attributes[3].ulValueLen = CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                                attributes[4].type = ckaYubicoHsmAuthAlgorithm
                                attributes[4].pValue = UnsafeMutableRawPointer(algorithmPointer)
                                attributes[4].ulValueLen = CK_ULONG(MemoryLayout<CK_ULONG>.size)
                                attributes[5].type = ckaYubicoHsmAuthRetries
                                attributes[5].pValue = UnsafeMutableRawPointer(retriesPointer)
                                attributes[5].ulValueLen = CK_ULONG(MemoryLayout<CK_ULONG>.size)
                                attributes[6].type = ckaYubicoHsmAuthTouchRequired
                                attributes[6].pValue = UnsafeMutableRawPointer(touchPointer)
                                attributes[6].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                                return attributes.withUnsafeMutableBufferPointer { buffer in
                                    C_GetAttributeValue(
                                        session,
                                        object,
                                        buffer.baseAddress,
                                        CK_ULONG(buffer.count)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    var parts = ["  \(object)"]
    if attributes[0].ulValueLen == CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size) {
        parts.append(objectClassName(objectClass))
    } else {
        parts.append("class unavailable")
    }
    var objectLabel: String?
    if let length = availableLength(
        attributes[1],
        capacity: objectAttributeBufferCapacity
    ) {
        let value = String(decoding: label.prefix(length), as: UTF8.self)
        if !value.isEmpty {
            objectLabel = value
            parts.append("label=\(value.debugDescription)")
        }
    }
    if let length = availableLength(
        attributes[2],
        capacity: objectAttributeBufferCapacity
    ), length > 0 {
        parts.append("id=\(hexString(identifier.prefix(length)))")
    }
    if attributes[3].ulValueLen == CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size) {
        parts.append("key=\(keyTypeName(keyType))")
    }
    if result != CKR_OK,
       result != CKR_ATTRIBUTE_TYPE_INVALID,
       result != CKR_ATTRIBUTE_SENSITIVE,
       result != CKR_BUFFER_TOO_SMALL
    {
        parts.append("attributes failed: \(result)")
    }
    let hasHsmAuthMetadata =
        attributes[4].ulValueLen == CK_ULONG(MemoryLayout<CK_ULONG>.size)
        && attributes[5].ulValueLen == CK_ULONG(MemoryLayout<CK_ULONG>.size)
        && attributes[6].ulValueLen == CK_ULONG(MemoryLayout<CK_BBOOL>.size)
    let credential: HsmAuthCredential? = if hasHsmAuthMetadata,
                                            let objectLabel,
                                            let source
    {
        HsmAuthCredential(
            label: objectLabel,
            source: source,
            algorithm: hsmAuthAlgorithm,
            retries: hsmAuthRetries,
            touchRequired: hsmAuthTouchRequired != CK_BBOOL(CK_FALSE)
        )
    } else {
        nil
    }
    if let credential {
        parts.append("YubiHSM Auth \(credential.algorithmName)")
        parts.append("retries=\(credential.retries)")
        parts.append("touch=\(credential.touchRequired)")
    }
    return ObjectInspection(
        description: parts.joined(separator: ", "),
        credential: credential
    )
}

private func objectInventory(
    session: CK_SESSION_HANDLE,
    title: String,
    source: String? = nil
) -> ObjectInventory {
    var objects = [CK_OBJECT_HANDLE]()
    var failure: String?
    let findInitResult = C_FindObjectsInit(session, nil, 0)
    if findInitResult == CKR_OK {
        while true {
            var batch = [CK_OBJECT_HANDLE](
                repeating: 0,
                count: objectFindBatchCapacity
            )
            var batchCount = CK_ULONG()
            let findResult = batch.withUnsafeMutableBufferPointer { buffer in
                C_FindObjects(
                    session,
                    buffer.baseAddress,
                    CK_ULONG(buffer.count),
                    &batchCount
                )
            }
            guard findResult == CKR_OK else {
                failure = "C_FindObjects failed: \(findResult)"
                break
            }
            guard Int(batchCount) <= batch.count else {
                failure = "C_FindObjects returned an invalid count: \(batchCount)"
                break
            }
            objects.append(contentsOf: batch.prefix(Int(batchCount)))
            if batchCount == 0 {
                break
            }
        }
        let findFinalResult = C_FindObjectsFinal(session)
        if findFinalResult != CKR_OK, failure == nil {
            failure = "C_FindObjectsFinal failed: \(findFinalResult)"
        }
    } else {
        failure = "C_FindObjectsInit failed: \(findInitResult)"
    }

    let inspections = objects.map {
        objectDescription(session: session, object: $0, source: source)
    }
    var lines = ["", "\(title): \(objects.count)"]
    lines.append(contentsOf: inspections.map(\.description))
    if let failure {
        lines.append("  \(failure)")
    }
    return ObjectInventory(
        lines: lines,
        credentials: inspections.compactMap(\.credential)
    )
}

private func publicObjectInventory(
    slot: CK_SLOT_ID,
    source: String
) -> ObjectInventory {
    var session = CK_SESSION_HANDLE()
    let openResult = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION),
        nil,
        nil,
        &session
    )
    guard openResult == CKR_OK else {
        return ObjectInventory(
            lines: ["", "Objects: C_OpenSession failed: \(openResult)"],
            credentials: []
        )
    }

    var inventory = objectInventory(
        session: session,
        title: "Objects (public session)",
        source: source
    )
    let closeResult = C_CloseSession(session)
    if closeResult != CKR_OK {
        inventory.lines.append("  C_CloseSession failed: \(closeResult)")
    }
    return inventory
}

private func authenticatedObjectInventory(
    slot: CK_SLOT_ID,
    credential: HsmAuthCredential
) -> [String] {
    var session = CK_SESSION_HANDLE()
    let openResult = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION),
        nil,
        nil,
        &session
    )
    guard openResult == CKR_OK else {
        return ["", "Authenticated objects: C_OpenSession failed: \(openResult)"]
    }

    var lines = [String]()
    var username = Array(credential.username.utf8)
    var password = Array(yubiHsmAuthPassword.utf8)
    let loginResult = password.withUnsafeMutableBufferPointer { passwordBuffer in
        username.withUnsafeMutableBufferPointer { usernameBuffer in
            C_LoginUser(
                session,
                CK_USER_TYPE(CKU_USER),
                passwordBuffer.baseAddress,
                CK_ULONG(passwordBuffer.count),
                usernameBuffer.baseAddress,
                CK_ULONG(usernameBuffer.count)
            )
        }
    }
    if loginResult == CKR_OK {
        lines.append("")
        lines.append("YubiHSM Auth login \(credential.username): success")
        lines.append(contentsOf: objectInventory(
            session: session,
            title: "Objects (authenticated session)"
        ).lines)
        let logoutResult = C_Logout(session)
        if logoutResult != CKR_OK {
            lines.append("C_Logout failed: \(logoutResult)")
        }
    } else if loginResult != CKR_FUNCTION_NOT_SUPPORTED {
        lines.append("")
        lines.append(
            "YubiHSM Auth login \(credential.username) failed: \(loginResult)"
        )
    }
    let closeResult = C_CloseSession(session)
    if closeResult != CKR_OK {
        lines.append("  C_CloseSession failed: \(closeResult)")
    }
    return lines
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

        var slotInventories = [SlotInventory]()
        for slot in slots.prefix(Int(count)) {
            var slotInfo = CK_SLOT_INFO()
            var tokenInfo = CK_TOKEN_INFO()
            let slotResult = C_GetSlotInfo(slot, &slotInfo)
            let tokenResult = C_GetTokenInfo(slot, &tokenInfo)
            guard slotResult == CKR_OK, tokenResult == CKR_OK else {
                lines.append("Slot \(slot) query failed: \(slotResult)/\(tokenResult)")
                continue
            }
            let description = paddedString(slotInfo.slotDescription)
            let tokenLabel = paddedString(tokenInfo.label)
            let serial = paddedString(tokenInfo.serialNumber)
            let source = serial.isEmpty ? description : serial
            slotInventories.append(SlotInventory(
                slot: slot,
                description: description,
                tokenLabel: tokenLabel,
                serial: serial,
                objects: publicObjectInventory(slot: slot, source: source)
            ))
        }

        let credentials = slotInventories.flatMap(\.objects.credentials)
        lines.append("")
        lines.append("YubiHSM Auth credentials: \(credentials.count)")
        lines.append(contentsOf: credentials.map { "  \($0.description)" })
        let selectedCredential = credentials.first
        if let selectedCredential {
            lines.append("Selected credential: \(selectedCredential.description)")
        }

        for inventory in slotInventories {
            lines.append("")
            lines.append("Slot \(inventory.slot): \(inventory.description)")
            lines.append("Token: \(inventory.tokenLabel)")
            lines.append("Serial: \(inventory.serial)")
            lines.append(contentsOf: inventory.objects.lines)
            if let selectedCredential {
                lines.append(contentsOf: authenticatedObjectInventory(
                    slot: inventory.slot,
                    credential: selectedCredential
                ))
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
