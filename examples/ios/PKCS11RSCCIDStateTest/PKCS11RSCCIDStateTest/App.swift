import CryptoTokenKit
import PKCS11RS
import UIKit

// This diagnostic app intentionally keeps Yubico's public factory-default PIV
// PIN in its UI field for repeated manual tests. Production pkcs11rs code does
// not receive or retain it except during an explicit login call.
private let factoryDefaultPivPin = "123456"

private enum TestMode: Int {
    case usb
    case nfc

    var title: String { self == .usb ? "USB" : "NFC" }
}

private struct TestInput {
    let mode: TestMode
    let serial: String
    let pin: String
}

private struct SlotPair {
    let piv: CK_SLOT_ID
    let hsmAuth: CK_SLOT_ID
    let serial: String
}

private struct SigningKey {
    let handle: CK_OBJECT_HANDLE
    let identifier: UInt8
    let label: String
}

private enum HarnessFailure: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let message): message
        }
    }
}

private func rvDescription(_ value: CK_RV) -> String {
    let code = String(format: "0x%llx", UInt64(value))
    guard let name = PKCS11RS_GetReturnValueName(value) else { return code }
    return "\(String(cString: name)) (\(code))"
}

private func paddedString<T>(_ value: T) -> String {
    withUnsafeBytes(of: value) { bytes in
        String(decoding: bytes, as: UTF8.self)
            .trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
    }
}

private func requireOK(_ result: CK_RV, _ operation: String) throws {
    guard result == CKR_OK else {
        throw HarnessFailure.message("\(operation) failed: \(rvDescription(result))")
    }
}

private func zero(_ bytes: inout [UInt8]) {
    _ = bytes.withUnsafeMutableBytes { buffer in
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
    }
}

private final class RawPeerAttempt {
    private let card: TKSmartCard
    private let completion = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var completed = false
    private var acquired = false
    private var failure: String?

    init() throws {
        guard let manager = TKSmartCardSlotManager.default else {
            throw HarnessFailure.message("CryptoTokenKit has no slot manager")
        }
        let cards = manager.slotNames.compactMap { name in
            manager.slotNamed(name)?.makeSmartCard()
        }
        guard cards.count == 1, let card = cards.first else {
            throw HarnessFailure.message(
                "Raw peer requires exactly one inserted CryptoTokenKit card; found \(cards.count)"
            )
        }
        self.card = card
    }

    func start() {
        card.isSensitive = true
        card.beginSession { [self] success, error in
            lock.lock()
            completed = true
            acquired = success
            failure = error?.localizedDescription
            lock.unlock()
            completion.signal()
        }
    }

    func hasCompleted(within seconds: Double) -> Bool {
        completion.wait(timeout: .now() + seconds) == .success
    }

    func result() -> (acquired: Bool, failure: String?) {
        lock.lock()
        defer { lock.unlock() }
        return (completed && acquired, failure)
    }

    func selectHsmAuth(timeout seconds: Double = 5) throws {
        let state = result()
        guard state.acquired else {
            throw HarnessFailure.message(
                "Raw peer did not acquire the card: \(state.failure ?? "no result")"
            )
        }
        let aid: [UInt8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01]
        var command: [UInt8] = [0x00, 0xa4, 0x04, 0x00, UInt8(aid.count)]
        command.append(contentsOf: aid)
        command.append(0x00)
        let transmitted = DispatchSemaphore(value: 0)
        var response: Data?
        var failure: Error?
        card.transmit(Data(command)) { value, error in
            response = value
            failure = error
            transmitted.signal()
        }
        guard transmitted.wait(timeout: .now() + seconds) == .success else {
            throw HarnessFailure.message("Raw YubiHSM Auth SELECT timed out")
        }
        guard failure == nil, let response, response.suffix(2) == Data([0x90, 0x00]) else {
            let suffix = response.map { $0.suffix(2).map { String(format: "%02X", $0) }.joined() }
                ?? "no response"
            throw HarnessFailure.message(
                "Raw YubiHSM Auth SELECT failed: \(failure?.localizedDescription ?? suffix)"
            )
        }
    }

    func end() {
        if result().acquired {
            card.endSession()
        }
    }
}

private final class CCIDStateHarness {
    private var initialized = false
    private var pivSession = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
    private var signingKey: SigningKey?
    private var armedNFCSerial: String?

    deinit {
        finalize()
    }

    private func configuration(for input: TestInput) throws -> String {
        var object: [String: Any] = [
            "version": 1,
            "logging": ["level": "debug"],
            "hardware": ["discovery": input.mode == .usb],
            "ccid": ["applications": ["piv", "hsmauth"]],
            "nfc": ["discovery": input.mode == .nfc],
        ]
        if !input.serial.isEmpty {
            object["slots"] = ["serials": [input.serial]]
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func initialize(_ input: TestInput) throws {
        finalize()
        let json = try configuration(for: input)
        var arguments = CK_C_INITIALIZE_ARGS()
        arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
        let result = json.withCString { bytes in
            arguments.pReserved = UnsafeMutableRawPointer(mutating: bytes)
            return C_Initialize(&arguments)
        }
        try requireOK(result, "C_Initialize")
        initialized = true
    }

    private func presentSlots() throws -> [CK_SLOT_ID] {
        var count = CK_ULONG()
        try requireOK(C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count), "C_GetSlotList(size)")
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        let result = slots.withUnsafeMutableBufferPointer { buffer in
            C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
        }
        try requireOK(result, "C_GetSlotList")
        guard Int(count) <= slots.count else {
            throw HarnessFailure.message("C_GetSlotList returned an invalid count")
        }
        return Array(slots.prefix(Int(count)))
    }

    private func findSlotPair(expectedSerial: String) throws -> SlotPair {
        var piv = [(CK_SLOT_ID, String)]()
        var hsmAuth = [(CK_SLOT_ID, String)]()
        for slot in try presentSlots() {
            var info = CK_TOKEN_INFO()
            guard C_GetTokenInfo(slot, &info) == CKR_OK else { continue }
            let label = paddedString(info.label)
            let serial = paddedString(info.serialNumber)
            if label.hasPrefix("PIV #") {
                piv.append((slot, serial))
            } else if label.hasPrefix("HSM Auth #") {
                hsmAuth.append((slot, serial))
            }
        }
        let serials = Set(piv.map(\.1)).intersection(Set(hsmAuth.map(\.1)))
            .filter { expectedSerial.isEmpty || $0 == expectedSerial }
        guard serials.count == 1, let serial = serials.first else {
            throw HarnessFailure.message(
                "Expected exactly one YubiKey with both PIV and YubiHSM Auth; matching serials: \(serials.sorted()); PIV slots: \(piv); YubiHSM Auth slots: \(hsmAuth)"
            )
        }
        guard piv.filter({ $0.1 == serial }).count == 1,
              hsmAuth.filter({ $0.1 == serial }).count == 1,
              let pivSlot = piv.first(where: { $0.1 == serial })?.0,
              let hsmSlot = hsmAuth.first(where: { $0.1 == serial })?.0
        else {
            throw HarnessFailure.message("The selected serial has ambiguous applet slots")
        }
        return SlotPair(piv: pivSlot, hsmAuth: hsmSlot, serial: serial)
    }

    private func openPiv(_ slot: CK_SLOT_ID) throws {
        var session = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        try requireOK(
            C_OpenSession(slot, CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &session),
            "C_OpenSession(PIV)"
        )
        pivSession = session
    }

    private func login(pin: String) throws {
        var bytes = Array(pin.utf8)
        defer { zero(&bytes) }
        let result = bytes.withUnsafeMutableBufferPointer { buffer in
            C_Login(
                pivSession,
                CK_USER_TYPE(CKU_USER),
                buffer.baseAddress,
                CK_ULONG(buffer.count)
            )
        }
        guard result == CKR_OK || result == CKR_USER_ALREADY_LOGGED_IN else {
            throw HarnessFailure.message("C_Login(PIV) failed: \(rvDescription(result))")
        }
    }

    private func attributes(
        object: CK_OBJECT_HANDLE
    ) -> (
        keyType: CK_KEY_TYPE,
        always: CK_BBOOL,
        id: UInt8,
        label: String,
        parameters: [UInt8]
    )? {
        var keyType = CK_KEY_TYPE()
        var always = CK_BBOOL()
        var identifier = [UInt8](repeating: 0, count: 8)
        var label = [UInt8](repeating: 0, count: 128)
        var parameters = [UInt8](repeating: 0, count: 32)
        let labelCapacity = label.count
        let parameterCapacity = parameters.count
        var labelLength = 0
        var parameterLength = 0
        var result = CK_RV(CKR_GENERAL_ERROR)
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
            withUnsafeMutablePointer(to: &always) { alwaysPointer in
                identifier.withUnsafeMutableBytes { identifierBuffer in
                    label.withUnsafeMutableBytes { labelBuffer in
                        parameters.withUnsafeMutableBytes { parameterBuffer in
                            var values = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 5)
                            values[0].type = CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE)
                            values[0].pValue = UnsafeMutableRawPointer(keyTypePointer)
                            values[0].ulValueLen = CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                            values[1].type = CK_ATTRIBUTE_TYPE(CKA_ALWAYS_AUTHENTICATE)
                            values[1].pValue = UnsafeMutableRawPointer(alwaysPointer)
                            values[1].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            values[2].type = CK_ATTRIBUTE_TYPE(CKA_ID)
                            values[2].pValue = identifierBuffer.baseAddress
                            values[2].ulValueLen = CK_ULONG(identifierBuffer.count)
                            values[3].type = CK_ATTRIBUTE_TYPE(CKA_LABEL)
                            values[3].pValue = labelBuffer.baseAddress
                            values[3].ulValueLen = CK_ULONG(labelBuffer.count)
                            values[4].type = CK_ATTRIBUTE_TYPE(CKA_EC_PARAMS)
                            values[4].pValue = parameterBuffer.baseAddress
                            values[4].ulValueLen = CK_ULONG(parameterBuffer.count)
                            result = values.withUnsafeMutableBufferPointer { buffer in
                                C_GetAttributeValue(
                                    pivSession,
                                    object,
                                    buffer.baseAddress,
                                    CK_ULONG(buffer.count)
                                )
                            }
                            if result == CKR_OK,
                               values[2].ulValueLen == 1,
                               values[3].ulValueLen <= CK_ULONG(labelCapacity),
                               values[4].ulValueLen <= CK_ULONG(parameterCapacity)
                            {
                                labelLength = Int(values[3].ulValueLen)
                                parameterLength = Int(values[4].ulValueLen)
                            }
                        }
                    }
                }
            }
        }
        guard result == CKR_OK else { return nil }
        return (
            keyType,
            always,
            identifier[0],
            String(decoding: label.prefix(labelLength), as: UTF8.self),
            Array(parameters.prefix(parameterLength))
        )
    }

    private func findOnceP256SigningKey() throws -> SigningKey {
        var objectClass = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
        var canSign = CK_BBOOL(CK_TRUE)
        var template = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 2)
        let initialize = withUnsafeMutablePointer(to: &objectClass) { classPointer in
            withUnsafeMutablePointer(to: &canSign) { signPointer in
                template[0].type = CK_ATTRIBUTE_TYPE(CKA_CLASS)
                template[0].pValue = UnsafeMutableRawPointer(classPointer)
                template[0].ulValueLen = CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)
                template[1].type = CK_ATTRIBUTE_TYPE(CKA_SIGN)
                template[1].pValue = UnsafeMutableRawPointer(signPointer)
                template[1].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                return template.withUnsafeMutableBufferPointer { buffer in
                    C_FindObjectsInit(pivSession, buffer.baseAddress, CK_ULONG(buffer.count))
                }
            }
        }
        try requireOK(initialize, "C_FindObjectsInit(PIV signing keys)")
        defer { _ = C_FindObjectsFinal(pivSession) }

        var candidates = [SigningKey]()
        let p256Parameters: [UInt8] = [
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]
        while true {
            var handles = [CK_OBJECT_HANDLE](repeating: 0, count: 16)
            var count = CK_ULONG()
            let result = handles.withUnsafeMutableBufferPointer { buffer in
                C_FindObjects(pivSession, buffer.baseAddress, CK_ULONG(buffer.count), &count)
            }
            try requireOK(result, "C_FindObjects(PIV signing keys)")
            if count == 0 { break }
            for handle in handles.prefix(Int(count)) {
                guard let value = attributes(object: handle),
                      value.keyType == CK_KEY_TYPE(CKK_EC),
                      value.parameters == p256Parameters,
                      value.always == CK_BBOOL(CK_FALSE),
                      value.id != 2,
                      value.id != 4
                else { continue }
                candidates.append(SigningKey(
                    handle: handle,
                    identifier: value.id,
                    label: value.label
                ))
            }
        }
        guard let key = candidates.sorted(by: { $0.identifier < $1.identifier }).first else {
            throw HarnessFailure.message(
                "No P-256 signing key with PIN policy ONCE was found. Use PIV 9A, 9D, or a retired slot; 9C/ALWAYS and 9E/NEVER are excluded."
            )
        }
        return key
    }

    private func sign(_ key: SigningKey, operation: String) throws {
        var mechanism = CK_MECHANISM(
            mechanism: CK_MECHANISM_TYPE(CKM_ECDSA),
            pParameter: nil,
            ulParameterLen: 0
        )
        try requireOK(C_SignInit(pivSession, &mechanism, key.handle), "\(operation) C_SignInit")
        var digest = [UInt8](0..<32)
        var signature = [UInt8](repeating: 0, count: 128)
        var signatureLength = CK_ULONG(signature.count)
        let result = digest.withUnsafeMutableBufferPointer { digestBuffer in
            signature.withUnsafeMutableBufferPointer { signatureBuffer in
                C_Sign(
                    pivSession,
                    digestBuffer.baseAddress,
                    CK_ULONG(digestBuffer.count),
                    signatureBuffer.baseAddress,
                    &signatureLength
                )
            }
        }
        try requireOK(result, "\(operation) C_Sign")
        guard signatureLength == 64 else {
            throw HarnessFailure.message("\(operation) returned \(signatureLength) bytes, expected 64")
        }
    }

    private func sessionState() throws -> CK_STATE {
        var info = CK_SESSION_INFO()
        try requireOK(C_GetSessionInfo(pivSession, &info), "C_GetSessionInfo(PIV)")
        return info.state
    }

    private func switchToHsmAuth(_ slot: CK_SLOT_ID) throws {
        var session = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        try requireOK(
            C_OpenSession(slot, CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &session),
            "C_OpenSession(YubiHSM Auth)"
        )
        defer { _ = C_CloseSession(session) }
        try requireOK(
            PKCS11RS_RefreshTokenObjects(slot),
            "PKCS11RS_RefreshTokenObjects(YubiHSM Auth)"
        )
        try requireOK(C_FindObjectsInit(session, nil, 0), "C_FindObjectsInit(YubiHSM Auth)")
        var object = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        var count = CK_ULONG()
        let find = C_FindObjects(session, &object, 1, &count)
        let final = C_FindObjectsFinal(session)
        try requireOK(find, "C_FindObjects(YubiHSM Auth)")
        try requireOK(final, "C_FindObjectsFinal(YubiHSM Auth)")
    }

    private func expectLoggedOutSign(_ key: SigningKey) throws -> CK_RV {
        var mechanism = CK_MECHANISM(
            mechanism: CK_MECHANISM_TYPE(CKM_ECDSA),
            pParameter: nil,
            ulParameterLen: 0
        )
        let initialize = C_SignInit(pivSession, &mechanism, key.handle)
        if initialize == CKR_USER_NOT_LOGGED_IN { return initialize }
        guard initialize == CKR_OK else { return initialize }
        var digest = [UInt8](0..<32)
        var signature = [UInt8](repeating: 0, count: 128)
        var signatureLength = CK_ULONG(signature.count)
        return digest.withUnsafeMutableBufferPointer { digestBuffer in
            signature.withUnsafeMutableBufferPointer { signatureBuffer in
                C_Sign(
                    pivSession,
                    digestBuffer.baseAddress,
                    CK_ULONG(digestBuffer.count),
                    signatureBuffer.baseAddress,
                    &signatureLength
                )
            }
        }
    }

    private func establishOwner(_ input: TestInput) throws -> (SlotPair, SigningKey, [String]) {
        guard !input.pin.isEmpty else {
            throw HarnessFailure.message("Enter the PIV PIN")
        }
        try initialize(input)
        let slots = try findSlotPair(expectedSerial: input.serial)
        try openPiv(slots.piv)
        try login(pin: input.pin)
        let key = try findOnceP256SigningKey()
        try sign(key, operation: "initial")
        signingKey = key
        return (slots, key, [
            "Selected YubiKey serial \(slots.serial)",
            "Selected \(key.label) (CKA_ID \(key.identifier))",
            "Initial PIV login and signature succeeded",
        ])
    }

    func runRetainedStateTest(_ input: TestInput) -> String {
        var lines = ["\(input.mode.title) retained-state test"]
        var peer: RawPeerAttempt?
        do {
            let (slots, key, established) = try establishOwner(input)
            lines.append(contentsOf: established)

            _ = try presentSlots()
            try sign(key, operation: "after C_GetSlotList")
            lines.append("C_GetSlotList did not disturb PIV authentication")

            if input.mode == .usb {
                let attempt = try RawPeerAttempt()
                peer = attempt
                attempt.start()
                guard !attempt.hasCompleted(within: 2) else {
                    let result = attempt.result()
                    throw HarnessFailure.message(
                        "Competing CryptoTokenKit session completed while pkcs11rs owned the card: \(result.failure ?? "acquired=\(result.acquired)")"
                    )
                }
                lines.append("Competing CryptoTokenKit session remained blocked for 2 seconds")
                try sign(key, operation: "while peer waits")
                lines.append("PIV signature still succeeded while the peer waited")
            }

            try switchToHsmAuth(slots.hsmAuth)
            lines.append("Listed live YubiHSM Auth credentials through its PKCS #11 slot")
            let state = try sessionState()
            guard state == CK_STATE(CKS_RO_PUBLIC_SESSION) else {
                throw HarnessFailure.message(
                    "PIV session state after applet switch was \(state), expected CKS_RO_PUBLIC_SESSION"
                )
            }
            lines.append("Existing PIV session remained open and became public")
            let rejected = try expectLoggedOutSign(key)
            guard rejected == CKR_USER_NOT_LOGGED_IN else {
                throw HarnessFailure.message(
                    "Protected PIV operation after applet switch returned \(rvDescription(rejected)), expected CKR_USER_NOT_LOGGED_IN"
                )
            }
            lines.append("Protected PIV operation was rejected as logged out")

            try login(pin: input.pin)
            try sign(key, operation: "after renewed login")
            lines.append("Fresh PIV login restored signing")

            finalize()
            if let peer {
                guard peer.hasCompleted(within: 10) else {
                    throw HarnessFailure.message(
                        "Competing CryptoTokenKit session did not acquire after C_Finalize"
                    )
                }
                try peer.selectHsmAuth()
                peer.end()
                lines.append("Peer acquired after C_Finalize and selected YubiHSM Auth")
            }
            lines.append("PASS")
        } catch {
            finalize()
            if let peer {
                if !peer.result().acquired {
                    _ = peer.hasCompleted(within: 5)
                }
                peer.end()
            }
            lines.append("FAIL: \(error)")
        }
        return lines.joined(separator: "\n")
    }

    func armNFCRemovalTest(_ input: TestInput) -> String {
        var input = input
        input = TestInput(mode: .nfc, serial: input.serial, pin: input.pin)
        var lines = ["NFC removal/reacquisition test"]
        do {
            let (slots, _, established) = try establishOwner(input)
            lines.append(contentsOf: established)
            armedNFCSerial = slots.serial
            lines.append("")
            lines.append("ARMED: remove the YubiKey from the NFC field, wait for iOS to notice, then tap Resume NFC removal test.")
        } catch {
            finalize()
            lines.append("FAIL: \(error)")
        }
        return lines.joined(separator: "\n")
    }

    func resumeNFCRemovalTest(_ input: TestInput) -> String {
        var lines = ["NFC removal/reacquisition test"]
        do {
            guard initialized,
                  let serial = armedNFCSerial,
                  let key = signingKey
            else {
                throw HarnessFailure.message("No NFC removal test is armed")
            }
            guard !input.pin.isEmpty else {
                throw HarnessFailure.message("Re-enter the PIV PIN before resuming")
            }
            _ = try presentSlots()
            lines.append("Reacquired YubiKey serial \(serial)")
            let state = try sessionState()
            guard state == CK_STATE(CKS_RO_PUBLIC_SESSION) else {
                throw HarnessFailure.message(
                    "PIV session remained authenticated; the NFC card may not have been removed long enough"
                )
            }
            lines.append("Reacquisition cleared the logical PIV login state")
            let rejected = try expectLoggedOutSign(key)
            guard rejected == CKR_USER_NOT_LOGGED_IN else {
                throw HarnessFailure.message(
                    "Protected PIV operation after reacquisition returned \(rvDescription(rejected)), expected CKR_USER_NOT_LOGGED_IN"
                )
            }
            lines.append("Protected operation required a new login")
            try login(pin: input.pin)
            try sign(key, operation: "after NFC reacquisition login")
            lines.append("Fresh login and signature succeeded")
            lines.append("PASS")
        } catch {
            lines.append("FAIL: \(error)")
        }
        finalize()
        return lines.joined(separator: "\n")
    }

    func prepareUSBOwner(_ input: TestInput) -> String {
        var input = input
        input = TestInput(mode: .usb, serial: input.serial, pin: input.pin)
        var lines = ["USB owner instance"]
        do {
            let (_, _, established) = try establishOwner(input)
            lines.append(contentsOf: established)
            lines.append("OWNER READY")
        } catch {
            finalize()
            lines.append("FAIL: \(error)")
        }
        return lines.joined(separator: "\n")
    }

    func signWithUSBOwner() -> String {
        do {
            guard initialized, let key = signingKey else {
                throw HarnessFailure.message("USB owner is not prepared")
            }
            try sign(key, operation: "owner follow-up")
            return "OWNER SIGNATURE SUCCEEDED"
        } catch {
            return "FAIL: \(error)"
        }
    }

    func releaseUSBOwner() -> String {
        finalize()
        return "OWNER RELEASED"
    }

    func finalize() {
        if pivSession != CK_SESSION_HANDLE(CK_INVALID_HANDLE) {
            _ = C_CloseSession(pivSession)
            pivSession = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        }
        signingKey = nil
        armedNFCSerial = nil
        if initialized {
            _ = C_Finalize(nil)
            initialized = false
        }
    }
}

private final class TestViewController: UIViewController {
    private let serialField = UITextField()
    private let pinField = UITextField()
    private let runButton = UIButton(type: .system)
    private let armButton = UIButton(type: .system)
    private let resumeButton = UIButton(type: .system)
    private let ownerButton = UIButton(type: .system)
    private let ownerSignButton = UIButton(type: .system)
    private let ownerReleaseButton = UIButton(type: .system)
    private let reportView = UITextView()
    private let statusLabel = UILabel()
    var onRun: ((TestInput) -> Void)?
    var onArmNFC: ((TestInput) -> Void)?
    var onResumeNFC: ((TestInput) -> Void)?
    var onPrepareOwner: ((TestInput) -> Void)?
    var onOwnerSign: (() -> Void)?
    var onOwnerRelease: (() -> Void)?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let title = UILabel()
        title.font = .preferredFont(forTextStyle: .title2)
        title.text = "PKCS11RS CCID state test"

        let explanation = UILabel()
        explanation.numberOfLines = 0
        explanation.text =
            "Tests a retained CryptoTokenKit session, undisturbed PIV authentication, deliberate PIV/YubiHSM Auth switching, and NFC reacquisition. It never provisions or deletes keys."

        serialField.borderStyle = .roundedRect
        serialField.placeholder = "YubiKey serial (optional)"
        serialField.keyboardType = .numberPad
        serialField.autocorrectionType = .no
        serialField.accessibilityIdentifier = "serial"

        pinField.borderStyle = .roundedRect
        pinField.placeholder = "PIV PIN"
        pinField.keyboardType = .numberPad
        pinField.isSecureTextEntry = true
        pinField.textContentType = .password
        pinField.text = factoryDefaultPivPin
        pinField.accessibilityIdentifier = "pin"

        configure(runButton, title: "Run USB retained-state test", action: #selector(runTest))
        configure(armButton, title: "Arm NFC removal test", action: #selector(armNFC))
        configure(resumeButton, title: "Resume NFC removal test", action: #selector(resumeNFC))
        configure(ownerButton, title: "Prepare USB owner", action: #selector(prepareOwner))
        configure(ownerSignButton, title: "Sign with USB owner", action: #selector(signOwner))
        configure(ownerReleaseButton, title: "Release USB owner", action: #selector(releaseOwner))
        ownerButton.accessibilityIdentifier = "prepareOwner"
        ownerSignButton.accessibilityIdentifier = "ownerSign"
        ownerReleaseButton.accessibilityIdentifier = "ownerRelease"

        statusLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        statusLabel.textColor = .secondaryLabel
        statusLabel.accessibilityIdentifier = "status"

        reportView.backgroundColor = .secondarySystemBackground
        reportView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        reportView.isEditable = false
        reportView.text = "Choose a test. The factory-default PIV PIN is prefilled."
        reportView.accessibilityIdentifier = "report"

        let controls = UIStackView(arrangedSubviews: [
            title,
            explanation,
            serialField,
            pinField,
            runButton,
            armButton,
            resumeButton,
            ownerButton,
            ownerSignButton,
            ownerReleaseButton,
            statusLabel,
        ])
        controls.axis = .vertical
        controls.spacing = 9
        controls.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(controls)
        reportView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(reportView)

        let safe = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            controls.topAnchor.constraint(equalTo: safe.topAnchor, constant: 12),
            controls.leadingAnchor.constraint(equalTo: safe.leadingAnchor, constant: 16),
            controls.trailingAnchor.constraint(equalTo: safe.trailingAnchor, constant: -16),
            reportView.topAnchor.constraint(equalTo: controls.bottomAnchor, constant: 12),
            reportView.leadingAnchor.constraint(equalTo: safe.leadingAnchor, constant: 16),
            reportView.trailingAnchor.constraint(equalTo: safe.trailingAnchor, constant: -16),
            reportView.bottomAnchor.constraint(equalTo: safe.bottomAnchor, constant: -12),
            reportView.heightAnchor.constraint(greaterThanOrEqualToConstant: 150),
        ])
    }

    private func configure(_ button: UIButton, title: String, action: Selector) {
        button.configuration = .bordered()
        button.configuration?.title = title
        button.addTarget(self, action: action, for: .touchUpInside)
    }

    private func input(for mode: TestMode) -> TestInput {
        TestInput(
            mode: mode,
            serial: serialField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
            pin: pinField.text ?? ""
        )
    }

    func begin(_ operation: String) {
        view.endEditing(true)
        setButtons(enabled: false)
        statusLabel.text = operation
    }

    func finish(_ report: String) {
        reportView.text = report
        statusLabel.text = report.contains("FAIL:") ? "Failed" : "Ready"
        setButtons(enabled: true)
    }

    private func setButtons(enabled: Bool) {
        [runButton, armButton, resumeButton, ownerButton, ownerSignButton, ownerReleaseButton]
            .forEach { $0.isEnabled = enabled }
    }

    @objc private func runTest() { onRun?(input(for: .usb)) }
    @objc private func armNFC() { onArmNFC?(input(for: .nfc)) }
    @objc private func resumeNFC() { onResumeNFC?(input(for: .nfc)) }
    @objc private func prepareOwner() { onPrepareOwner?(input(for: .usb)) }
    @objc private func signOwner() { onOwnerSign?() }
    @objc private func releaseOwner() { onOwnerRelease?() }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    private let controller = TestViewController()
    private let queue = DispatchQueue(label: "com.nilssoncrypto.PKCS11RSCCIDStateTest")
    private let harness = CCIDStateHarness()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        controller.onRun = { [weak self] input in
            self?.perform("Running \(input.mode.title) test…") {
                self?.harness.runRetainedStateTest(input) ?? "Tester was released"
            }
        }
        controller.onArmNFC = { [weak self] input in
            self?.perform("Present the NFC YubiKey…") {
                self?.harness.armNFCRemovalTest(input) ?? "Tester was released"
            }
        }
        controller.onResumeNFC = { [weak self] input in
            self?.perform("Re-present the NFC YubiKey…") {
                self?.harness.resumeNFCRemovalTest(input) ?? "Tester was released"
            }
        }
        controller.onPrepareOwner = { [weak self] input in
            self?.perform("Preparing USB owner…") {
                self?.harness.prepareUSBOwner(input) ?? "Tester was released"
            }
        }
        controller.onOwnerSign = { [weak self] in
            self?.perform("Signing with USB owner…") {
                self?.harness.signWithUSBOwner() ?? "Tester was released"
            }
        }
        controller.onOwnerRelease = { [weak self] in
            self?.perform("Releasing USB owner…") {
                self?.harness.releaseUSBOwner() ?? "Tester was released"
            }
        }
        return true
    }

    func connectWindow(to scene: UIWindowScene) -> UIWindow {
        let window = UIWindow(windowScene: scene)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        return window
    }

    private func perform(_ status: String, operation: @escaping () -> String) {
        controller.begin(status)
        queue.async { [weak self] in
            let report = operation()
            DispatchQueue.main.async {
                self?.controller.finish(report)
            }
        }
    }

    func applicationWillTerminate(_ application: UIApplication) {
        queue.sync { harness.finalize() }
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let scene = scene as? UIWindowScene,
              let delegate = UIApplication.shared.delegate as? AppDelegate
        else { return }
        window = delegate.connectWindow(to: scene)
    }
}
