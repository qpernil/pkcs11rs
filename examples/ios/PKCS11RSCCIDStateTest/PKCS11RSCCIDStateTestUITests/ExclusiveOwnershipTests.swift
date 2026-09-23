import PKCS11RS
import XCTest

private final class SecondInstanceResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    func set(_ value: String) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    func get() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func describe(_ result: CK_RV) -> String {
    let code = String(format: "0x%llx", UInt64(result))
    guard let name = PKCS11RS_GetReturnValueName(result) else { return code }
    return "\(String(cString: name)) (\(code))"
}

private func discoverHsmAuthSlot() -> String {
    var count = CK_ULONG()
    let result = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count)
    guard result == CKR_OK, count == 1 else {
        return "C_GetSlotList(size): \(describe(result)), count=\(count)"
    }
    var slot = CK_SLOT_ID()
    var capacity = CK_ULONG(1)
    let list = C_GetSlotList(CK_BBOOL(CK_TRUE), &slot, &capacity)
    guard list == CKR_OK, capacity == 1 else {
        return "C_GetSlotList(buffer): \(describe(list)), count=\(capacity)"
    }
    var info = CK_TOKEN_INFO()
    let token = C_GetTokenInfo(slot, &info)
    guard token == CKR_OK else {
        return "C_GetTokenInfo: \(describe(token))"
    }
    let label = withUnsafeBytes(of: info.label) { bytes in
        String(decoding: bytes, as: UTF8.self)
            .trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
    }
    return label.hasPrefix("HSM Auth #") ? "PASS: \(label)" : "unexpected token label: \(label)"
}

final class ExclusiveOwnershipTests: XCTestCase {
    func testSecondPkcs11InstanceCannotUseUSBCardWhileOwnedAndRecovers() throws {
        let environment = ProcessInfo.processInfo.environment
        let serial = environment["PKCS11RS_TEST_YUBIKEY_SERIAL"] ?? ""

        let app = XCUIApplication()
        app.launch()
        if !serial.isEmpty {
            let serialField = app.textFields["serial"]
            XCTAssertTrue(serialField.waitForExistence(timeout: 5))
            serialField.tap()
            serialField.typeText(serial)
        }
        XCTAssertTrue(app.secureTextFields["pin"].waitForExistence(timeout: 5))
        // Tap Prepare USB owner on the physical phone. The application owns
        // its diagnostic factory-default PIN field; this independent test
        // process deliberately never reads or retains it.
        waitForReport(app, containing: "OWNER READY", timeout: 120)

        var configuration: [String: Any] = [
            "version": 1,
            "logging": ["level": "debug"],
            "hardware": ["discovery": true],
            "ccid": ["applications": ["hsmauth"]],
            "nfc": ["discovery": false],
        ]
        if !serial.isEmpty {
            configuration["slots"] = ["serials": [serial]]
        }
        let encoded = try JSONSerialization.data(
            withJSONObject: configuration,
            options: [.sortedKeys]
        )
        let json = String(decoding: encoded, as: UTF8.self)
        var arguments = CK_C_INITIALIZE_ARGS()
        arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
        let initialize = json.withCString { bytes in
            arguments.pReserved = UnsafeMutableRawPointer(mutating: bytes)
            return C_Initialize(&arguments)
        }
        guard initialize == CKR_OK else {
            XCTFail("C_Initialize: \(describe(initialize))")
            return
        }

        let completed = DispatchSemaphore(value: 0)
        let second = SecondInstanceResult()
        DispatchQueue.global(qos: .userInitiated).async {
            second.set(discoverHsmAuthSlot())
            completed.signal()
        }

        // CryptoTokenKit may either keep the probe waiting or let its short
        // applet-discovery APDUs time out. Neither may expose the owned card.
        _ = completed.wait(timeout: .now() + 5)
        XCTAssertFalse(
            second.get()?.hasPrefix("PASS:") == true,
            "The second pkcs11rs instance acquired the card while it was owned"
        )

        app.buttons["ownerSign"].tap()
        waitForReport(app, containing: "OWNER SIGNATURE SUCCEEDED", timeout: 10)
        XCTAssertFalse(
            second.get()?.hasPrefix("PASS:") == true,
            "The second pkcs11rs instance acquired the card before owner release"
        )
        app.buttons["ownerRelease"].tap()
        waitForReport(app, containing: "OWNER RELEASED", timeout: 10)

        if second.get() == nil {
            guard completed.wait(timeout: .now() + 30) == .success else {
                XCTFail("The initial second-process discovery did not finish after owner release")
                return
            }
        }

        // A probe that timed out while the card was owned has already returned
        // zero slots. Start a fresh discovery after release; do not interpret
        // that earlier result as a post-release failure.
        let deadline = Date().addingTimeInterval(15)
        var discovery = second.get() ?? "initial discovery returned no result"
        while !discovery.hasPrefix("PASS:") && Date() < deadline {
            discovery = discoverHsmAuthSlot()
            if !discovery.hasPrefix("PASS:") {
                Thread.sleep(forTimeInterval: 0.5)
            }
        }
        XCTAssertTrue(discovery.hasPrefix("PASS:"), discovery)
        _ = C_Finalize(nil)
    }

    private func waitForReport(
        _ app: XCUIApplication,
        containing text: String,
        timeout: TimeInterval
    ) {
        let report = app.textViews["report"]
        XCTAssertTrue(report.waitForExistence(timeout: 5))
        let predicate = NSPredicate(format: "value CONTAINS %@", text)
        expectation(for: predicate, evaluatedWith: report)
        waitForExpectations(timeout: timeout)
    }
}
