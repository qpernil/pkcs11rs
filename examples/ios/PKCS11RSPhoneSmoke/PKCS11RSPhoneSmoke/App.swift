import PKCS11RS
import UIKit

private let connectorURLKey = "PKCS11RSConnectorURL"
private let fallbackConnectorURL = "http://192.168.1.169:12345"
private let initialSlotListCapacity = 10
private let objectFindBatchCapacity = 64
private let objectAttributeBufferCapacity = 1024
private let yubiHsmAuthPassword = "password"
private let softwareTokenName = "iPhone smoke"
private let softwareTokenModel = "Software token"
private let softwareTokenPIN = "password"
private let softwareX25519Label = "iPhone smoke X25519"
private let softwareX25519ID = Array("iphone-smoke-x25519".utf8)
private let x25519Parameters: [UInt8] = [
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
]
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
    let publicKey: [UInt8]?

    func username(authenticationKeyID: [UInt8]) -> String? {
        guard authenticationKeyID.count == 2 else {
            return nil
        }
        let identifier = authenticationKeyID.map {
            String(format: "%02X", $0)
        }.joined()
        return ":\(identifier)\(label)@\(source)"
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
    let publicKey: PublicKeyIdentity?
}

private struct PublicKeyIdentity {
    let id: [UInt8]
    let ecPoint: [UInt8]
}

private struct ObjectInventory {
    var lines: [String]
    let credentials: [HsmAuthCredential]
    let publicKeys: [PublicKeyIdentity]
}

private struct SlotInventory {
    let slot: CK_SLOT_ID
    let description: String
    let tokenLabel: String
    let serial: String
    let isYubiHsm: Bool
    let objects: ObjectInventory
}

private struct ConnectorConfiguration {
    let url: String
    let tokenStoragePath: String
    let json: String
}

private func connectorConfiguration() -> ConnectorConfiguration {
    let environment = ProcessInfo.processInfo.environment
    let defaults = UserDefaults.standard
    let url = environment["PKCS11RS_YUBIHSM_URLS"]
        ?? defaults.string(forKey: connectorURLKey)
        ?? fallbackConnectorURL
    defaults.set(url, forKey: connectorURLKey)
    let tokenStoragePath = FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
    )[0]
        .appendingPathComponent("pkcs11rs-smoke", isDirectory: true)
        .path

    let object: [String: Any] = [
        "version": 1,
        "logging": [
            "level": "debug",
        ],
        "storage": [
            "tokens": tokenStoragePath,
        ],
        "software": [
            "slots": [[
                "name": softwareTokenName,
                "discovery_pin": softwareTokenPIN,
            ]],
        ],
        "yubihsm": [
            "urls": [url],
            "public_discovery": "0001password",
        ],
        "nfc": [
            "discovery": true,
        ],
    ]
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return ConnectorConfiguration(
        url: url,
        tokenStoragePath: tokenStoragePath,
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
    var ecPoint = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var attributes = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 8)

    let result = withUnsafeMutablePointer(to: &objectClass) { objectClassPointer in
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
            withUnsafeMutablePointer(to: &hsmAuthAlgorithm) { algorithmPointer in
                withUnsafeMutablePointer(to: &hsmAuthRetries) { retriesPointer in
                    withUnsafeMutablePointer(to: &hsmAuthTouchRequired) { touchPointer in
                        label.withUnsafeMutableBytes { labelBuffer in
                            identifier.withUnsafeMutableBytes { identifierBuffer in
                                ecPoint.withUnsafeMutableBytes { ecPointBuffer in
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
                                    attributes[7].type = CK_ATTRIBUTE_TYPE(CKA_EC_POINT)
                                    attributes[7].pValue = ecPointBuffer.baseAddress
                                    attributes[7].ulValueLen = CK_ULONG(ecPointBuffer.count)
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
    let objectIdentifier = availableLength(
        attributes[2],
        capacity: objectAttributeBufferCapacity
    ).flatMap { length in
        length > 0 ? Array(identifier.prefix(length)) : nil
    }
    if let objectIdentifier {
        parts.append("id=\(hexString(objectIdentifier[...]))")
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
            touchRequired: hsmAuthTouchRequired != CK_BBOOL(CK_FALSE),
            publicKey: nil
        )
    } else {
        nil
    }
    if let credential {
        parts.append("YubiHSM Auth \(credential.algorithmName)")
        parts.append("retries=\(credential.retries)")
        parts.append("touch=\(credential.touchRequired)")
    }
    let publicKey: PublicKeyIdentity? = if attributes[0].ulValueLen
        == CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size),
        attributes[3].ulValueLen == CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size),
        objectClass == CK_OBJECT_CLASS(CKO_PUBLIC_KEY),
        keyType == CK_KEY_TYPE(CKK_EC),
        let objectIdentifier,
        let length = availableLength(
            attributes[7],
            capacity: objectAttributeBufferCapacity
        ), length > 0
    {
        PublicKeyIdentity(
            id: objectIdentifier,
            ecPoint: Array(ecPoint.prefix(length))
        )
    } else {
        nil
    }
    return ObjectInspection(
        description: parts.joined(separator: ", "),
        credential: credential,
        publicKey: publicKey
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
    let publicKeys = inspections.compactMap(\.publicKey)
    let credentials = inspections.compactMap(\.credential).map { credential in
        HsmAuthCredential(
            label: credential.label,
            source: credential.source,
            algorithm: credential.algorithm,
            retries: credential.retries,
            touchRequired: credential.touchRequired,
            publicKey: publicKeys.first {
                $0.id == Array(credential.label.utf8)
            }?.ecPoint
        )
    }
    return ObjectInventory(
        lines: lines,
        credentials: credentials,
        publicKeys: publicKeys
    )
}

private func softwareTokenLabel() -> [UInt8] {
    var label = [UInt8](repeating: 0x20, count: 32)
    let name = Array(softwareTokenName.utf8.prefix(label.count))
    label.replaceSubrange(0..<name.count, with: name)
    return label
}

private func login(
    session: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pin: String
) -> CK_RV {
    var bytes = Array(pin.utf8)
    return bytes.withUnsafeMutableBufferPointer { buffer in
        C_Login(
            session,
            userType,
            buffer.baseAddress,
            CK_ULONG(buffer.count)
        )
    }
}

private func initializeSoftwareToken(slot: CK_SLOT_ID) -> CK_RV {
    var pin = Array(softwareTokenPIN.utf8)
    var label = softwareTokenLabel()
    return pin.withUnsafeMutableBufferPointer { pinBuffer in
        label.withUnsafeMutableBufferPointer { labelBuffer in
            C_InitToken(
                slot,
                pinBuffer.baseAddress,
                CK_ULONG(pinBuffer.count),
                labelBuffer.baseAddress
            )
        }
    }
}

private func initializeSoftwareUserPIN(session: CK_SESSION_HANDLE) -> CK_RV {
    var pin = Array(softwareTokenPIN.utf8)
    return pin.withUnsafeMutableBufferPointer { buffer in
        C_InitPIN(session, buffer.baseAddress, CK_ULONG(buffer.count))
    }
}

private func findSoftwareX25519PrivateKey(
    session: CK_SESSION_HANDLE
) -> (result: CK_RV, object: CK_OBJECT_HANDLE?) {
    var objectClass = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
    var keyType = CK_KEY_TYPE(CKK_EC_MONTGOMERY)
    var identifier = softwareX25519ID
    var attributes = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 3)
    let initialize = withUnsafeMutablePointer(to: &objectClass) { classPointer in
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
            identifier.withUnsafeMutableBytes { identifierBuffer in
                attributes[0].type = CK_ATTRIBUTE_TYPE(CKA_CLASS)
                attributes[0].pValue = UnsafeMutableRawPointer(classPointer)
                attributes[0].ulValueLen = CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)
                attributes[1].type = CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE)
                attributes[1].pValue = UnsafeMutableRawPointer(keyTypePointer)
                attributes[1].ulValueLen = CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                attributes[2].type = CK_ATTRIBUTE_TYPE(CKA_ID)
                attributes[2].pValue = identifierBuffer.baseAddress
                attributes[2].ulValueLen = CK_ULONG(identifierBuffer.count)
                return attributes.withUnsafeMutableBufferPointer { buffer in
                    C_FindObjectsInit(
                        session,
                        buffer.baseAddress,
                        CK_ULONG(buffer.count)
                    )
                }
            }
        }
    }
    guard initialize == CKR_OK else {
        return (initialize, nil)
    }

    var object = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var count = CK_ULONG()
    let find = C_FindObjects(session, &object, 1, &count)
    let finalize = C_FindObjectsFinal(session)
    guard find == CKR_OK else {
        return (find, nil)
    }
    guard finalize == CKR_OK else {
        return (finalize, nil)
    }
    return (CK_RV(CKR_OK), count == 0 ? nil : object)
}

private func generateSoftwareX25519KeyPair(
    session: CK_SESSION_HANDLE
) -> (result: CK_RV, publicKey: CK_OBJECT_HANDLE, privateKey: CK_OBJECT_HANDLE) {
    var token = CK_BBOOL(CK_TRUE)
    var derive = CK_BBOOL(CK_TRUE)
    var parameters = x25519Parameters
    var identifier = softwareX25519ID
    var label = Array(softwareX25519Label.utf8)
    var publicKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var privateKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var mechanism = CK_MECHANISM(
        mechanism: CK_MECHANISM_TYPE(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
        pParameter: nil,
        ulParameterLen: 0
    )
    let result = withUnsafeMutablePointer(to: &token) { tokenPointer in
        withUnsafeMutablePointer(to: &derive) { derivePointer in
            parameters.withUnsafeMutableBytes { parameterBuffer in
                identifier.withUnsafeMutableBytes { identifierBuffer in
                    label.withUnsafeMutableBytes { labelBuffer in
                        var publicAttributes = [CK_ATTRIBUTE](
                            repeating: CK_ATTRIBUTE(),
                            count: 4
                        )
                        publicAttributes[0].type = CK_ATTRIBUTE_TYPE(CKA_TOKEN)
                        publicAttributes[0].pValue = UnsafeMutableRawPointer(tokenPointer)
                        publicAttributes[0].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                        publicAttributes[1].type = CK_ATTRIBUTE_TYPE(CKA_LABEL)
                        publicAttributes[1].pValue = labelBuffer.baseAddress
                        publicAttributes[1].ulValueLen = CK_ULONG(labelBuffer.count)
                        publicAttributes[2].type = CK_ATTRIBUTE_TYPE(CKA_ID)
                        publicAttributes[2].pValue = identifierBuffer.baseAddress
                        publicAttributes[2].ulValueLen = CK_ULONG(identifierBuffer.count)
                        publicAttributes[3].type = CK_ATTRIBUTE_TYPE(CKA_EC_PARAMS)
                        publicAttributes[3].pValue = parameterBuffer.baseAddress
                        publicAttributes[3].ulValueLen = CK_ULONG(parameterBuffer.count)

                        var privateAttributes = [CK_ATTRIBUTE](
                            repeating: CK_ATTRIBUTE(),
                            count: 4
                        )
                        privateAttributes[0].type = CK_ATTRIBUTE_TYPE(CKA_TOKEN)
                        privateAttributes[0].pValue = UnsafeMutableRawPointer(tokenPointer)
                        privateAttributes[0].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                        privateAttributes[1].type = CK_ATTRIBUTE_TYPE(CKA_LABEL)
                        privateAttributes[1].pValue = labelBuffer.baseAddress
                        privateAttributes[1].ulValueLen = CK_ULONG(labelBuffer.count)
                        privateAttributes[2].type = CK_ATTRIBUTE_TYPE(CKA_ID)
                        privateAttributes[2].pValue = identifierBuffer.baseAddress
                        privateAttributes[2].ulValueLen = CK_ULONG(identifierBuffer.count)
                        privateAttributes[3].type = CK_ATTRIBUTE_TYPE(CKA_DERIVE)
                        privateAttributes[3].pValue = UnsafeMutableRawPointer(derivePointer)
                        privateAttributes[3].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)

                        return publicAttributes.withUnsafeMutableBufferPointer { publicBuffer in
                            privateAttributes.withUnsafeMutableBufferPointer { privateBuffer in
                                C_GenerateKeyPair(
                                    session,
                                    &mechanism,
                                    publicBuffer.baseAddress,
                                    CK_ULONG(publicBuffer.count),
                                    privateBuffer.baseAddress,
                                    CK_ULONG(privateBuffer.count),
                                    &publicKey,
                                    &privateKey
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    return (result, publicKey, privateKey)
}

private func softwareObjectInventory(
    slot: CK_SLOT_ID,
    tokenInfo: CK_TOKEN_INFO
) -> ObjectInventory {
    var lines = ["", "Persistent software token \(softwareTokenName.debugDescription):"]
    let tokenInitialized = tokenInfo.flags & CK_FLAGS(CKF_TOKEN_INITIALIZED) != 0
    let userPINInitialized = tokenInfo.flags & CK_FLAGS(CKF_USER_PIN_INITIALIZED) != 0
    if !tokenInitialized {
        let initialize = initializeSoftwareToken(slot: slot)
        guard initialize == CKR_OK else {
            lines.append("  C_InitToken failed: \(initialize)")
            return ObjectInventory(lines: lines, credentials: [], publicKeys: [])
        }
        lines.append("  initialized persistent token")
    }

    var session = CK_SESSION_HANDLE()
    let open = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
        nil,
        nil,
        &session
    )
    guard open == CKR_OK else {
        lines.append("  C_OpenSession failed: \(open)")
        return ObjectInventory(lines: lines, credentials: [], publicKeys: [])
    }

    var failure: String?
    if !tokenInitialized || !userPINInitialized {
        let soLogin = login(
            session: session,
            userType: CK_USER_TYPE(CKU_SO),
            pin: softwareTokenPIN
        )
        if soLogin != CKR_OK {
            failure = "C_Login(CKU_SO) failed: \(soLogin)"
        } else {
            let initializePIN = initializeSoftwareUserPIN(session: session)
            if initializePIN == CKR_OK {
                lines.append("  initialized user PIN")
            } else {
                failure = "C_InitPIN failed: \(initializePIN)"
            }
            let logout = C_Logout(session)
            if logout != CKR_OK, failure == nil {
                failure = "C_Logout(CKU_SO) failed: \(logout)"
            }
        }
    }

    var userLoggedIn = false
    if failure == nil {
        let userLogin = login(
            session: session,
            userType: CK_USER_TYPE(CKU_USER),
            pin: softwareTokenPIN
        )
        if userLogin == CKR_OK {
            userLoggedIn = true
        } else {
            failure = "C_Login(CKU_USER) failed: \(userLogin)"
        }
    }

    if failure == nil {
        let found = findSoftwareX25519PrivateKey(session: session)
        if found.result != CKR_OK {
            failure = "X25519 key search failed: \(found.result)"
        } else if found.object != nil {
            lines.append("  X25519 keypair already present")
        } else {
            let generated = generateSoftwareX25519KeyPair(session: session)
            if generated.result == CKR_OK {
                lines.append(
                    "  generated X25519 keypair: public \(generated.publicKey), private \(generated.privateKey)"
                )
            } else {
                failure = "C_GenerateKeyPair(X25519) failed: \(generated.result)"
            }
        }
    }

    var inventory = if let failure {
        ObjectInventory(
            lines: ["", "Objects: skipped after \(failure)"],
            credentials: [],
            publicKeys: []
        )
    } else {
        objectInventory(session: session, title: "Objects (authenticated software session)")
    }
    if let failure {
        lines.append("  \(failure)")
    }
    if userLoggedIn {
        let logout = C_Logout(session)
        if logout != CKR_OK {
            inventory.lines.append("  C_Logout failed: \(logout)")
        }
    }
    let close = C_CloseSession(session)
    if close != CKR_OK {
        inventory.lines.append("  C_CloseSession failed: \(close)")
    }
    inventory.lines.insert(contentsOf: lines, at: 0)
    return inventory
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
            credentials: [],
            publicKeys: []
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
    credential: HsmAuthCredential,
    authenticationKeyID: [UInt8]
) -> [String] {
    guard let usernameValue = credential.username(
        authenticationKeyID: authenticationKeyID
    ) else {
        return ["", "YubiHSM Auth login: invalid Authentication Key CKA_ID"]
    }
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
    var username = Array(usernameValue.utf8)
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
        lines.append("YubiHSM Auth login \(usernameValue): success")
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
            "YubiHSM Auth login \(usernameValue) failed: \(loginResult)"
        )
    }
    let closeResult = C_CloseSession(session)
    if closeResult != CKR_OK {
        lines.append("  C_CloseSession failed: \(closeResult)")
    }
    return lines
}

private final class InspectionViewController: UIViewController {
    private let statusLabel = UILabel()
    private let refreshButton = UIButton(type: .system)
    private let inventoryView = UITextView()
    var onRefresh: (() -> Void)?
    private var refreshStartedAt: Date?
    private var refreshTimer: Timer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        statusLabel.textColor = .secondaryLabel
        statusLabel.isHidden = true
        view.addSubview(statusLabel)

        refreshButton.translatesAutoresizingMaskIntoConstraints = false
        refreshButton.configuration = .bordered()
        refreshButton.configuration?.title = "Refresh"
        refreshButton.addTarget(self, action: #selector(refresh), for: .touchUpInside)
        view.addSubview(refreshButton)

        inventoryView.translatesAutoresizingMaskIntoConstraints = false
        inventoryView.backgroundColor = .systemBackground
        inventoryView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        inventoryView.isEditable = false
        inventoryView.textContainerInset = UIEdgeInsets(top: 8, left: 12, bottom: 20, right: 12)
        view.addSubview(inventoryView)
        NSLayoutConstraint.activate([
            refreshButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            refreshButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            statusLabel.centerYAnchor.constraint(equalTo: refreshButton.centerYAnchor),
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            inventoryView.topAnchor.constraint(equalTo: refreshButton.bottomAnchor, constant: 4),
            inventoryView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            inventoryView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            inventoryView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    func beginRefresh() {
        refreshTimer?.invalidate()
        refreshButton.isEnabled = false
        refreshStartedAt = Date()
        updateRefreshStatus()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) {
            [weak self] _ in
            self?.updateRefreshStatus()
        }
    }

    func showInventory(_ inventory: String) {
        endOperation()
        inventoryView.text = inventory
    }

    private func endOperation() {
        refreshTimer?.invalidate()
        refreshTimer = nil
        refreshStartedAt = nil
        statusLabel.isHidden = true
        refreshButton.isEnabled = true
    }

    private func updateRefreshStatus() {
        guard let refreshStartedAt else { return }
        let seconds = max(0, Int(Date().timeIntervalSince(refreshStartedAt)))
        statusLabel.text = "Working… \(seconds)s"
        statusLabel.isHidden = false
    }

    @objc private func refresh() {
        onRefresh?()
    }
}

private final class ModuleInspector {
    private var initialized = false

    private func initialize(configuration: ConnectorConfiguration) -> CK_RV {
        if !initialized {
            var arguments = CK_C_INITIALIZE_ARGS()
            arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
            let result = configuration.json.withCString { json in
                arguments.pReserved = UnsafeMutableRawPointer(mutating: json)
                return C_Initialize(&arguments)
            }
            guard result == CKR_OK else {
                return result
            }
            initialized = true
        }
        return CKR_OK
    }

    private func moduleInformation(
        configuration: ConnectorConfiguration
    ) -> (lines: [String]?, error: String?) {
        let initialize = initialize(configuration: configuration)
        guard initialize == CKR_OK else {
            return (nil, "C_Initialize failed: \(initialize)")
        }

        var info = CK_INFO()
        let getInfo = C_GetInfo(&info)
        guard getInfo == CKR_OK else {
            return (nil, "C_GetInfo failed: \(getInfo)")
        }

        return ([
            "PKCS11RS on iPhone",
            "",
            "Cryptoki: \(info.cryptokiVersion.major).\(info.cryptokiVersion.minor)",
            "Manufacturer: \(paddedString(info.manufacturerID))",
            "Library: \(paddedString(info.libraryDescription)) \(info.libraryVersion.major).\(info.libraryVersion.minor)",
            "Configuration: C_Initialize JSON",
            "Connector: \(configuration.url)",
            "Token storage: \(configuration.tokenStoragePath)",
        ], nil)
    }

    func initializeAndDescribe(configuration: ConnectorConfiguration) -> String {
        let information = moduleInformation(configuration: configuration)
        guard var lines = information.lines else {
            return information.error ?? "Module initialization failed"
        }
        lines.append("")
        lines.append("Tap Refresh to discover slots and inspect tokens.")
        return lines.joined(separator: "\n")
    }

    func inspect(configuration: ConnectorConfiguration) -> String {
        let module = moduleInformation(configuration: configuration)
        guard let information = module.lines else {
            return module.error ?? "Module inspection failed"
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

        var lines = information
        lines.append("")
        lines.append("Token-present slots: \(count)")

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
            let tokenModel = paddedString(tokenInfo.model)
            let serial = paddedString(tokenInfo.serialNumber)
            let source = serial.isEmpty ? description : serial
            let managesSoftwareToken = tokenModel == softwareTokenModel
                && tokenLabel == softwareTokenName
            let objects = managesSoftwareToken
                ? softwareObjectInventory(slot: slot, tokenInfo: tokenInfo)
                : publicObjectInventory(slot: slot, source: source)
            slotInventories.append(SlotInventory(
                slot: slot,
                description: description,
                tokenLabel: tokenLabel,
                serial: serial,
                isYubiHsm: tokenLabel.hasPrefix("YubiHSM #"),
                objects: objects
            ))
        }

        slotInventories = slotInventories.filter { !$0.isYubiHsm }
            + slotInventories.filter(\.isYubiHsm)

        let credentials = slotInventories.flatMap(\.objects.credentials)
        lines.append("")
        lines.append("YubiHSM Auth credentials: \(credentials.count)")
        if credentials.isEmpty {
            lines.append(
                "  Discovery produced no credential (canceled, unavailable, or unsupported token)."
            )
        } else {
            lines.append(contentsOf: credentials.map { "  \($0.description)" })
        }
        let selectedCredential = credentials.first
        if let selectedCredential {
            lines.append("Selected credential: \(selectedCredential.description)")
            lines.append("Authentication key: match by public CKA_EC_POINT")
        }

        for inventory in slotInventories {
            lines.append("")
            lines.append("Slot \(inventory.slot): \(inventory.description)")
            lines.append("Token: \(inventory.tokenLabel)")
            lines.append("Serial: \(inventory.serial)")
            lines.append(contentsOf: inventory.objects.lines)
            if inventory.isYubiHsm, let selectedCredential {
                let matches = selectedCredential.publicKey.map { credentialPublicKey in
                    inventory.objects.publicKeys.filter {
                        $0.ecPoint == credentialPublicKey
                            && $0.id.count == 2
                    }
                } ?? []
                if matches.count == 1 {
                    lines.append(
                        "Matched Authentication Key ID: \(hexString(matches[0].id[...]))"
                    )
                    lines.append(contentsOf: authenticatedObjectInventory(
                        slot: inventory.slot,
                        credential: selectedCredential,
                        authenticationKeyID: matches[0].id
                    ))
                } else {
                    lines.append(
                        "YubiHSM Auth public-key matches: \(matches.count); login skipped"
                    )
                }
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
    private let inspectionQueue = DispatchQueue(
        label: "com.qpernil.PKCS11RSSmoke.inspection",
        qos: .default
    )
    private let moduleInspector = ModuleInspector()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        controller.onRefresh = { [weak self] in
            self?.refresh()
        }
        initializeModule()

        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        inspectionQueue.sync {
            moduleInspector.finalize()
        }
    }

    private func refresh() {
        let configuration = connectorConfiguration()
        controller.beginRefresh()
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = moduleInspector.inspect(configuration: configuration)
            DispatchQueue.main.async {
                self.controller.showInventory(result)
            }
        }
    }

    private func initializeModule() {
        let configuration = connectorConfiguration()
        controller.beginRefresh()
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = moduleInspector.initializeAndDescribe(configuration: configuration)
            DispatchQueue.main.async {
                self.controller.showInventory(result)
            }
        }
    }
}
