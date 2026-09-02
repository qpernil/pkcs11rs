import PKCS11RS
import UIKit

private let connectorURLKey = "PKCS11RSConnectorURL"
private let fallbackConnectorURL = "http://plankan-9.duckdns.org:12345"
private let initialSlotListCapacity = 10
private let objectFindBatchCapacity = 64
private let objectAttributeBufferCapacity = 1024
private let yubiHsmAuthPassword = "password"
private let platformCredentialName = "iphone-qpernil"
private let platformCredentialLabel = "iPhone qpernil"
private let platformAuthenticationKeyID = CK_ULONG(0x1004)
private let platformDomains = CK_ULONG(0xffff)
private let platformCapabilities = [UInt8](repeating: 0xff, count: 8)
private let softwareTokenName = "iPhone smoke"
private let softwareTokenModel = "Software token"
private let softwareTokenPIN = "password"
private let softwareX25519Label = "iPhone smoke X25519"
private let softwareX25519ID = Array("iphone-smoke-x25519".utf8)
private let softwareX25519SecretLength = 32
private let x25519Parameters: [UInt8] = [
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
]
private let softwareMlDsaLabel = "iPhone smoke ML-DSA-87"
private let softwareMlDsaID = Array("iphone-smoke-ml-dsa-87".utf8)
private let softwareMlDsaMessageLength = 32
private let softwareMlKemLabel = "iPhone smoke ML-KEM-1024"
private let softwareMlKemID = Array("iphone-smoke-ml-kem-1024".utf8)
private let softwareMlKemSecretLength = 32
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
    let credentials = inspections.compactMap(\.credential)
    return ObjectInventory(
        lines: lines,
        credentials: credentials
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

private func findSoftwareKey(
    session: CK_SESSION_HANDLE,
    objectClass: CK_OBJECT_CLASS,
    keyType: CK_KEY_TYPE,
    identifier: [UInt8]
) -> (result: CK_RV, object: CK_OBJECT_HANDLE?) {
    var objectClass = objectClass
    var keyType = keyType
    var identifier = identifier
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

private func generateSoftwarePostQuantumKeyPair(
    session: CK_SESSION_HANDLE,
    mechanismType: CK_MECHANISM_TYPE,
    parameterSet: CK_ULONG,
    label: String,
    identifier: [UInt8],
    publicUsageAttribute: CK_ATTRIBUTE_TYPE,
    privateUsageAttribute: CK_ATTRIBUTE_TYPE
) -> (result: CK_RV, publicKey: CK_OBJECT_HANDLE, privateKey: CK_OBJECT_HANDLE) {
    var token = CK_BBOOL(CK_TRUE)
    var publicUsage = CK_BBOOL(CK_TRUE)
    var privateUsage = CK_BBOOL(CK_TRUE)
    var parameterSet = parameterSet
    var identifier = identifier
    var label = Array(label.utf8)
    var publicKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var privateKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var mechanism = CK_MECHANISM(
        mechanism: mechanismType,
        pParameter: nil,
        ulParameterLen: 0
    )
    let result = withUnsafeMutablePointer(to: &token) { tokenPointer in
        withUnsafeMutablePointer(to: &publicUsage) { publicUsagePointer in
            withUnsafeMutablePointer(to: &privateUsage) { privateUsagePointer in
                withUnsafeMutablePointer(to: &parameterSet) { parameterSetPointer in
                    identifier.withUnsafeMutableBytes { identifierBuffer in
                        label.withUnsafeMutableBytes { labelBuffer in
                            var publicAttributes = [CK_ATTRIBUTE](
                                repeating: CK_ATTRIBUTE(),
                                count: 5
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
                            publicAttributes[3].type = CK_ATTRIBUTE_TYPE(CKA_PARAMETER_SET)
                            publicAttributes[3].pValue = UnsafeMutableRawPointer(parameterSetPointer)
                            publicAttributes[3].ulValueLen = CK_ULONG(
                                MemoryLayout<CK_ULONG>.size
                            )
                            publicAttributes[4].type = publicUsageAttribute
                            publicAttributes[4].pValue = UnsafeMutableRawPointer(publicUsagePointer)
                            publicAttributes[4].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)

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
                            privateAttributes[3].type = privateUsageAttribute
                            privateAttributes[3].pValue = UnsafeMutableRawPointer(privateUsagePointer)
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
    }
    return (result, publicKey, privateKey)
}

private func exerciseSoftwareMlDsa(
    session: CK_SESSION_HANDLE,
    publicKey: CK_OBJECT_HANDLE,
    privateKey: CK_OBJECT_HANDLE
) -> (
    result: CK_RV,
    operation: String,
    signatureLength: Int,
    signMilliseconds: Double,
    verifyMilliseconds: Double
) {
    var message = [UInt8](repeating: 0, count: softwareMlDsaMessageLength)
    var result = message.withUnsafeMutableBufferPointer { buffer in
        C_GenerateRandom(session, buffer.baseAddress, CK_ULONG(buffer.count))
    }
    guard result == CKR_OK else {
        return (result, "C_GenerateRandom", 0, 0, 0)
    }
    var mechanism = CK_MECHANISM(
        mechanism: CK_MECHANISM_TYPE(CKM_ML_DSA),
        pParameter: nil,
        ulParameterLen: 0
    )
    let signStart = ProcessInfo.processInfo.systemUptime
    result = C_SignInit(session, &mechanism, privateKey)
    guard result == CKR_OK else {
        return (result, "C_SignInit", 0, 0, 0)
    }
    var signatureLength = CK_ULONG()
    result = message.withUnsafeMutableBufferPointer { buffer in
        C_Sign(
            session,
            buffer.baseAddress,
            CK_ULONG(buffer.count),
            nil,
            &signatureLength
        )
    }
    guard result == CKR_OK else {
        return (result, "C_Sign(size)", 0, 0, 0)
    }
    var signature = [UInt8](repeating: 0, count: Int(signatureLength))
    result = message.withUnsafeMutableBufferPointer { messageBuffer in
        signature.withUnsafeMutableBufferPointer { signatureBuffer in
            C_Sign(
                session,
                messageBuffer.baseAddress,
                CK_ULONG(messageBuffer.count),
                signatureBuffer.baseAddress,
                &signatureLength
            )
        }
    }
    let signMilliseconds = (ProcessInfo.processInfo.systemUptime - signStart) * 1_000
    guard result == CKR_OK else {
        return (result, "C_Sign", 0, signMilliseconds, 0)
    }

    signature.removeSubrange(Int(signatureLength)..<signature.count)
    let verifyStart = ProcessInfo.processInfo.systemUptime
    result = C_VerifyInit(session, &mechanism, publicKey)
    guard result == CKR_OK else {
        return (result, "C_VerifyInit", signature.count, signMilliseconds, 0)
    }
    result = message.withUnsafeMutableBufferPointer { messageBuffer in
        signature.withUnsafeMutableBufferPointer { signatureBuffer in
            C_Verify(
                session,
                messageBuffer.baseAddress,
                CK_ULONG(messageBuffer.count),
                signatureBuffer.baseAddress,
                CK_ULONG(signatureBuffer.count)
            )
        }
    }
    let verifyMilliseconds = (ProcessInfo.processInfo.systemUptime - verifyStart) * 1_000
    return (
        result,
        "C_Verify",
        signature.count,
        signMilliseconds,
        verifyMilliseconds
    )
}

private func softwareAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    type: CK_ATTRIBUTE_TYPE
) -> (result: CK_RV, value: [UInt8]?) {
    var attribute = CK_ATTRIBUTE(
        type: type,
        pValue: nil,
        ulValueLen: 0
    )
    var result = C_GetAttributeValue(session, object, &attribute, 1)
    guard result == CKR_OK else {
        return (result, nil)
    }
    guard attribute.ulValueLen != CK_ULONG(CK_UNAVAILABLE_INFORMATION) else {
        return (CK_RV(CKR_ATTRIBUTE_SENSITIVE), nil)
    }
    var value = [UInt8](repeating: 0, count: Int(attribute.ulValueLen))
    result = value.withUnsafeMutableBufferPointer { buffer in
        attribute.pValue = UnsafeMutableRawPointer(buffer.baseAddress)
        attribute.ulValueLen = CK_ULONG(buffer.count)
        return C_GetAttributeValue(session, object, &attribute, 1)
    }
    guard result == CKR_OK else {
        return (result, nil)
    }
    value.removeSubrange(Int(attribute.ulValueLen)..<value.count)
    return (result, value)
}

private func exerciseSoftwareX25519(
    session: CK_SESSION_HANDLE,
    publicKey: CK_OBJECT_HANDLE,
    privateKey: CK_OBJECT_HANDLE
) -> (result: CK_RV, operation: String, deriveMilliseconds: Double) {
    let publicResult = softwareAttributeValue(
        session: session,
        object: publicKey,
        type: CK_ATTRIBUTE_TYPE(CKA_EC_POINT)
    )
    guard publicResult.result == CKR_OK, var publicPoint = publicResult.value else {
        return (publicResult.result, "C_GetAttributeValue(CKA_EC_POINT)", 0)
    }

    var token = CK_BBOOL(CK_FALSE)
    var sensitive = CK_BBOOL(CK_FALSE)
    var extractable = CK_BBOOL(CK_TRUE)
    var keyType = CK_KEY_TYPE(CKK_GENERIC_SECRET)
    var valueLength = CK_ULONG(softwareX25519SecretLength)
    var derivedSecret = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    defer {
        if derivedSecret != CK_OBJECT_HANDLE(CK_INVALID_HANDLE) {
            _ = C_DestroyObject(session, derivedSecret)
        }
    }

    let deriveStart = ProcessInfo.processInfo.systemUptime
    let result = publicPoint.withUnsafeMutableBufferPointer { publicBuffer in
        var parameters = CK_ECDH1_DERIVE_PARAMS(
            kdf: CK_EC_KDF_TYPE(CKD_NULL),
            ulSharedDataLen: 0,
            pSharedData: nil,
            ulPublicDataLen: CK_ULONG(publicBuffer.count),
            pPublicData: publicBuffer.baseAddress
        )
        var mechanism = CK_MECHANISM(
            mechanism: CK_MECHANISM_TYPE(CKM_ECDH1_DERIVE),
            pParameter: nil,
            ulParameterLen: CK_ULONG(MemoryLayout<CK_ECDH1_DERIVE_PARAMS>.size)
        )
        return withUnsafeMutablePointer(to: &parameters) { parametersPointer in
            mechanism.pParameter = UnsafeMutableRawPointer(parametersPointer)
            return withUnsafeMutablePointer(to: &token) { tokenPointer in
                withUnsafeMutablePointer(to: &sensitive) { sensitivePointer in
                    withUnsafeMutablePointer(to: &extractable) { extractablePointer in
                        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
                            withUnsafeMutablePointer(to: &valueLength) { valueLengthPointer in
                                var attributes = [
                                    CK_ATTRIBUTE(
                                        type: CK_ATTRIBUTE_TYPE(CKA_TOKEN),
                                        pValue: UnsafeMutableRawPointer(tokenPointer),
                                        ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                                    ),
                                    CK_ATTRIBUTE(
                                        type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE),
                                        pValue: UnsafeMutableRawPointer(sensitivePointer),
                                        ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                                    ),
                                    CK_ATTRIBUTE(
                                        type: CK_ATTRIBUTE_TYPE(CKA_EXTRACTABLE),
                                        pValue: UnsafeMutableRawPointer(extractablePointer),
                                        ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                                    ),
                                    CK_ATTRIBUTE(
                                        type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE),
                                        pValue: UnsafeMutableRawPointer(keyTypePointer),
                                        ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                                    ),
                                    CK_ATTRIBUTE(
                                        type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN),
                                        pValue: UnsafeMutableRawPointer(valueLengthPointer),
                                        ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)
                                    ),
                                ]
                                return attributes.withUnsafeMutableBufferPointer { buffer in
                                    C_DeriveKey(
                                        session,
                                        &mechanism,
                                        privateKey,
                                        buffer.baseAddress,
                                        CK_ULONG(buffer.count),
                                        &derivedSecret
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let deriveMilliseconds = (ProcessInfo.processInfo.systemUptime - deriveStart) * 1_000
    guard result == CKR_OK else {
        return (result, "C_DeriveKey", deriveMilliseconds)
    }
    let secret = softwareAttributeValue(
        session: session,
        object: derivedSecret,
        type: CK_ATTRIBUTE_TYPE(CKA_VALUE)
    )
    guard secret.result == CKR_OK else {
        return (secret.result, "C_GetAttributeValue(derived secret)", deriveMilliseconds)
    }
    guard let secretValue = secret.value,
          secretValue.count == softwareX25519SecretLength,
          secretValue.contains(where: { $0 != 0 }) else {
        return (CK_RV(CKR_GENERAL_ERROR), "X25519 shared-secret validation", deriveMilliseconds)
    }
    return (CK_RV(CKR_OK), "X25519 self-agreement", deriveMilliseconds)
}

private func exerciseSoftwareMlKem(
    session: CK_SESSION_HANDLE,
    publicKey: CK_OBJECT_HANDLE,
    privateKey: CK_OBJECT_HANDLE
) -> (
    result: CK_RV,
    operation: String,
    ciphertextLength: Int,
    encapsulateMilliseconds: Double,
    decapsulateMilliseconds: Double
) {
    var mechanism = CK_MECHANISM(
        mechanism: CK_MECHANISM_TYPE(CKM_ML_KEM),
        pParameter: nil,
        ulParameterLen: 0
    )
    var encapsulatedSecret = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var decapsulatedSecret = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    defer {
        if encapsulatedSecret != CK_OBJECT_HANDLE(CK_INVALID_HANDLE) {
            _ = C_DestroyObject(session, encapsulatedSecret)
        }
        if decapsulatedSecret != CK_OBJECT_HANDLE(CK_INVALID_HANDLE) {
            _ = C_DestroyObject(session, decapsulatedSecret)
        }
    }

    var token = CK_BBOOL(CK_FALSE)
    var sensitive = CK_BBOOL(CK_FALSE)
    var extractable = CK_BBOOL(CK_TRUE)
    var keyType = CK_KEY_TYPE(CKK_GENERIC_SECRET)
    var valueLength = CK_ULONG(softwareMlKemSecretLength)
    var ciphertextLength = CK_ULONG()
    let encapsulateStart = ProcessInfo.processInfo.systemUptime
    var result = C_EncapsulateKey(
        session,
        &mechanism,
        publicKey,
        nil,
        0,
        nil,
        &ciphertextLength,
        &encapsulatedSecret
    )
    guard result == CKR_OK else {
        return (result, "C_EncapsulateKey(size)", 0, 0, 0)
    }
    var ciphertext = [UInt8](repeating: 0, count: Int(ciphertextLength))
    result = withUnsafeMutablePointer(to: &token) { tokenPointer in
        withUnsafeMutablePointer(to: &sensitive) { sensitivePointer in
            withUnsafeMutablePointer(to: &extractable) { extractablePointer in
                withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
                    withUnsafeMutablePointer(to: &valueLength) { valueLengthPointer in
                        var attributes = [
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_TOKEN),
                                pValue: UnsafeMutableRawPointer(tokenPointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE),
                                pValue: UnsafeMutableRawPointer(sensitivePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_EXTRACTABLE),
                                pValue: UnsafeMutableRawPointer(extractablePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE),
                                pValue: UnsafeMutableRawPointer(keyTypePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN),
                                pValue: UnsafeMutableRawPointer(valueLengthPointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)
                            ),
                        ]
                        return attributes.withUnsafeMutableBufferPointer { attributeBuffer in
                            ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
                                C_EncapsulateKey(
                                    session,
                                    &mechanism,
                                    publicKey,
                                    attributeBuffer.baseAddress,
                                    CK_ULONG(attributeBuffer.count),
                                    ciphertextBuffer.baseAddress,
                                    &ciphertextLength,
                                    &encapsulatedSecret
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    let encapsulateMilliseconds =
        (ProcessInfo.processInfo.systemUptime - encapsulateStart) * 1_000
    guard result == CKR_OK else {
        return (result, "C_EncapsulateKey", 0, encapsulateMilliseconds, 0)
    }
    ciphertext.removeSubrange(Int(ciphertextLength)..<ciphertext.count)

    let decapsulateStart = ProcessInfo.processInfo.systemUptime
    result = withUnsafeMutablePointer(to: &token) { tokenPointer in
        withUnsafeMutablePointer(to: &sensitive) { sensitivePointer in
            withUnsafeMutablePointer(to: &extractable) { extractablePointer in
                withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
                    withUnsafeMutablePointer(to: &valueLength) { valueLengthPointer in
                        var attributes = [
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_TOKEN),
                                pValue: UnsafeMutableRawPointer(tokenPointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE),
                                pValue: UnsafeMutableRawPointer(sensitivePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_EXTRACTABLE),
                                pValue: UnsafeMutableRawPointer(extractablePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE),
                                pValue: UnsafeMutableRawPointer(keyTypePointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                            ),
                            CK_ATTRIBUTE(
                                type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN),
                                pValue: UnsafeMutableRawPointer(valueLengthPointer),
                                ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)
                            ),
                        ]
                        return attributes.withUnsafeMutableBufferPointer { attributeBuffer in
                            ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
                                C_DecapsulateKey(
                                    session,
                                    &mechanism,
                                    privateKey,
                                    attributeBuffer.baseAddress,
                                    CK_ULONG(attributeBuffer.count),
                                    ciphertextBuffer.baseAddress,
                                    CK_ULONG(ciphertextBuffer.count),
                                    &decapsulatedSecret
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    let decapsulateMilliseconds =
        (ProcessInfo.processInfo.systemUptime - decapsulateStart) * 1_000
    guard result == CKR_OK else {
        return (
            result,
            "C_DecapsulateKey",
            ciphertext.count,
            encapsulateMilliseconds,
            decapsulateMilliseconds
        )
    }

    let first = softwareAttributeValue(
        session: session,
        object: encapsulatedSecret,
        type: CK_ATTRIBUTE_TYPE(CKA_VALUE)
    )
    guard first.result == CKR_OK, let firstValue = first.value else {
        return (
            first.result,
            "C_GetAttributeValue(encapsulated secret)",
            ciphertext.count,
            encapsulateMilliseconds,
            decapsulateMilliseconds
        )
    }
    let second = softwareAttributeValue(
        session: session,
        object: decapsulatedSecret,
        type: CK_ATTRIBUTE_TYPE(CKA_VALUE)
    )
    guard second.result == CKR_OK, let secondValue = second.value else {
        return (
            second.result,
            "C_GetAttributeValue(decapsulated secret)",
            ciphertext.count,
            encapsulateMilliseconds,
            decapsulateMilliseconds
        )
    }
    guard firstValue.count == softwareMlKemSecretLength, firstValue == secondValue else {
        return (
            CK_RV(CKR_GENERAL_ERROR),
            "ML-KEM shared-secret comparison",
            ciphertext.count,
            encapsulateMilliseconds,
            decapsulateMilliseconds
        )
    }
    return (
        CK_RV(CKR_OK),
        "ML-KEM shared-secret comparison",
        ciphertext.count,
        encapsulateMilliseconds,
        decapsulateMilliseconds
    )
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
            return ObjectInventory(lines: lines, credentials: [])
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
        return ObjectInventory(lines: lines, credentials: [])
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
        let foundPublic = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PUBLIC_KEY),
            keyType: CK_KEY_TYPE(CKK_EC_MONTGOMERY),
            identifier: softwareX25519ID
        )
        let foundPrivate = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
            keyType: CK_KEY_TYPE(CKK_EC_MONTGOMERY),
            identifier: softwareX25519ID
        )
        var publicKey = foundPublic.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        var privateKey = foundPrivate.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        if foundPublic.result != CKR_OK {
            failure = "X25519 public-key search failed: \(foundPublic.result)"
        } else if foundPrivate.result != CKR_OK {
            failure = "X25519 private-key search failed: \(foundPrivate.result)"
        } else if foundPublic.object != nil, foundPrivate.object != nil {
            lines.append("  X25519 keypair already present")
        } else if foundPublic.object != nil || foundPrivate.object != nil {
            failure = "X25519 keypair is incomplete"
        } else {
            let generationStart = ProcessInfo.processInfo.systemUptime
            let generated = generateSoftwareX25519KeyPair(session: session)
            let generationMilliseconds =
                (ProcessInfo.processInfo.systemUptime - generationStart) * 1_000
            if generated.result == CKR_OK {
                publicKey = generated.publicKey
                privateKey = generated.privateKey
                lines.append(
                    String(
                        format: "  generated X25519 keypair in %.3f ms: public %llu, private %llu",
                        generationMilliseconds,
                        UInt64(generated.publicKey),
                        UInt64(generated.privateKey)
                    )
                )
            } else {
                failure = "C_GenerateKeyPair(X25519) failed: \(generated.result)"
            }
        }

        if failure == nil {
            let exercised = exerciseSoftwareX25519(
                session: session,
                publicKey: publicKey,
                privateKey: privateKey
            )
            if exercised.result == CKR_OK {
                lines.append(
                    String(
                        format: "  X25519 self-agreement %.3f ms (32-byte shared secret)",
                        exercised.deriveMilliseconds
                    )
                )
            } else {
                failure = "\(exercised.operation)(X25519) failed: \(exercised.result)"
            }
        }
    }

    if failure == nil {
        let foundPublic = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PUBLIC_KEY),
            keyType: CK_KEY_TYPE(CKK_ML_DSA),
            identifier: softwareMlDsaID
        )
        let foundPrivate = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
            keyType: CK_KEY_TYPE(CKK_ML_DSA),
            identifier: softwareMlDsaID
        )
        var publicKey = foundPublic.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        var privateKey = foundPrivate.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        if foundPublic.result != CKR_OK {
            failure = "ML-DSA-87 public-key search failed: \(foundPublic.result)"
        } else if foundPrivate.result != CKR_OK {
            failure = "ML-DSA-87 private-key search failed: \(foundPrivate.result)"
        } else if foundPublic.object != nil, foundPrivate.object != nil {
            lines.append("  ML-DSA-87 keypair already present")
        } else if foundPublic.object != nil || foundPrivate.object != nil {
            failure = "ML-DSA-87 keypair is incomplete"
        } else {
            let generationStart = ProcessInfo.processInfo.systemUptime
            let generated = generateSoftwarePostQuantumKeyPair(
                session: session,
                mechanismType: CK_MECHANISM_TYPE(CKM_ML_DSA_KEY_PAIR_GEN),
                parameterSet: CK_ULONG(CKP_ML_DSA_87),
                label: softwareMlDsaLabel,
                identifier: softwareMlDsaID,
                publicUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_VERIFY),
                privateUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_SIGN)
            )
            let generationMilliseconds =
                (ProcessInfo.processInfo.systemUptime - generationStart) * 1_000
            if generated.result == CKR_OK {
                publicKey = generated.publicKey
                privateKey = generated.privateKey
                lines.append(
                    String(
                        format: "  generated ML-DSA-87 keypair in %.3f ms: public %llu, private %llu",
                        generationMilliseconds,
                        UInt64(generated.publicKey),
                        UInt64(generated.privateKey)
                    )
                )
            } else {
                failure = "C_GenerateKeyPair(ML-DSA-87) failed: \(generated.result)"
            }
        }

        if failure == nil {
            let exercised = exerciseSoftwareMlDsa(
                session: session,
                publicKey: publicKey,
                privateKey: privateKey
            )
            if exercised.result == CKR_OK {
                lines.append(
                    String(
                        format: "  ML-DSA-87 sign %.3f ms, verify %.3f ms (%d-byte signature)",
                        exercised.signMilliseconds,
                        exercised.verifyMilliseconds,
                        exercised.signatureLength
                    )
                )
            } else {
                failure = "\(exercised.operation)(ML-DSA-87) failed: \(exercised.result)"
            }
        }
    }

    if failure == nil {
        let foundPublic = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PUBLIC_KEY),
            keyType: CK_KEY_TYPE(CKK_ML_KEM),
            identifier: softwareMlKemID
        )
        let foundPrivate = findSoftwareKey(
            session: session,
            objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
            keyType: CK_KEY_TYPE(CKK_ML_KEM),
            identifier: softwareMlKemID
        )
        var publicKey = foundPublic.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        var privateKey = foundPrivate.object ?? CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
        if foundPublic.result != CKR_OK {
            failure = "ML-KEM-1024 public-key search failed: \(foundPublic.result)"
        } else if foundPrivate.result != CKR_OK {
            failure = "ML-KEM-1024 private-key search failed: \(foundPrivate.result)"
        } else if foundPublic.object != nil, foundPrivate.object != nil {
            lines.append("  ML-KEM-1024 keypair already present")
        } else if foundPublic.object != nil || foundPrivate.object != nil {
            failure = "ML-KEM-1024 keypair is incomplete"
        } else {
            let generationStart = ProcessInfo.processInfo.systemUptime
            let generated = generateSoftwarePostQuantumKeyPair(
                session: session,
                mechanismType: CK_MECHANISM_TYPE(CKM_ML_KEM_KEY_PAIR_GEN),
                parameterSet: CK_ULONG(CKP_ML_KEM_1024),
                label: softwareMlKemLabel,
                identifier: softwareMlKemID,
                publicUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_ENCAPSULATE),
                privateUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_DECAPSULATE)
            )
            let generationMilliseconds =
                (ProcessInfo.processInfo.systemUptime - generationStart) * 1_000
            if generated.result == CKR_OK {
                publicKey = generated.publicKey
                privateKey = generated.privateKey
                lines.append(
                    String(
                        format: "  generated ML-KEM-1024 keypair in %.3f ms: public %llu, private %llu",
                        generationMilliseconds,
                        UInt64(generated.publicKey),
                        UInt64(generated.privateKey)
                    )
                )
            } else {
                failure = "C_GenerateKeyPair(ML-KEM-1024) failed: \(generated.result)"
            }
        }

        if failure == nil {
            let exercised = exerciseSoftwareMlKem(
                session: session,
                publicKey: publicKey,
                privateKey: privateKey
            )
            if exercised.result == CKR_OK {
                lines.append(
                    String(
                        format: "  ML-KEM-1024 encapsulate %.3f ms, decapsulate %.3f ms (%d-byte ciphertext, shared secret matched)",
                        exercised.encapsulateMilliseconds,
                        exercised.decapsulateMilliseconds,
                        exercised.ciphertextLength
                    )
                )
            } else {
                failure = "\(exercised.operation)(ML-KEM-1024) failed: \(exercised.result)"
            }
        }
    }

    var inventory = if let failure {
        ObjectInventory(
            lines: ["", "Objects: skipped after \(failure)"],
            credentials: []
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
    slot: CK_SLOT_ID
) -> [String] {
    let usernameValue = ":*"
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
        lines.append("Automatic credential login \(usernameValue): success")
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
            "Automatic credential login \(usernameValue) failed: \(loginResult)"
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
    private let provisionButton = UIButton(type: .system)
    private let inventoryView = UITextView()
    var onRefresh: (() -> Void)?
    var onProvision: ((Bool) -> Void)?
    private var platformCredentialProvisioned = false
    private var refreshStartedAt: Date?
    private var refreshTimer: Timer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let heading = UILabel()
        heading.font = .preferredFont(forTextStyle: .title2)
        heading.text = "PKCS #11 module inventory"

        let explanation = UILabel()
        explanation.font = .preferredFont(forTextStyle: .body)
        explanation.numberOfLines = 0
        explanation.text =
            "This Swift smoke app inspects PKCS #11 slots and provisions a platform credential."

        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        statusLabel.textColor = .secondaryLabel
        statusLabel.isHidden = true

        refreshButton.translatesAutoresizingMaskIntoConstraints = false
        refreshButton.configuration = .bordered()
        refreshButton.configuration?.title = "Refresh"
        refreshButton.addTarget(self, action: #selector(refresh), for: .touchUpInside)

        provisionButton.translatesAutoresizingMaskIntoConstraints = false
        provisionButton.configuration = .borderedProminent()
        provisionButton.configuration?.title = "Provision platform credential"
        provisionButton.addTarget(self, action: #selector(provision), for: .touchUpInside)

        let buttonRow = UIStackView(arrangedSubviews: [provisionButton, refreshButton])
        buttonRow.axis = .horizontal
        buttonRow.alignment = .center
        buttonRow.distribution = .equalSpacing

        let header = UIStackView(arrangedSubviews: [heading, explanation, buttonRow, statusLabel])
        header.translatesAutoresizingMaskIntoConstraints = false
        header.axis = .vertical
        header.alignment = .leading
        header.spacing = 12
        buttonRow.widthAnchor.constraint(equalTo: header.widthAnchor).isActive = true
        view.addSubview(header)

        inventoryView.translatesAutoresizingMaskIntoConstraints = false
        inventoryView.backgroundColor = .secondarySystemBackground
        inventoryView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        inventoryView.isEditable = false
        inventoryView.text = "Not inspected yet."
        view.addSubview(inventoryView)
        let safeArea = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: safeArea.topAnchor, constant: 20),
            header.leadingAnchor.constraint(equalTo: safeArea.leadingAnchor, constant: 20),
            header.trailingAnchor.constraint(equalTo: safeArea.trailingAnchor, constant: -20),
            inventoryView.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            inventoryView.leadingAnchor.constraint(equalTo: safeArea.leadingAnchor, constant: 20),
            inventoryView.trailingAnchor.constraint(equalTo: safeArea.trailingAnchor, constant: -20),
            inventoryView.bottomAnchor.constraint(equalTo: safeArea.bottomAnchor, constant: -20),
        ])
    }

    func beginRefresh() {
        refreshTimer?.invalidate()
        refreshButton.isEnabled = false
        provisionButton.isEnabled = false
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

    func setPlatformCredentialProvisioned(_ provisioned: Bool) {
        platformCredentialProvisioned = provisioned
        provisionButton.configuration?.title = provisioned
            ? "Unprovision platform credential"
            : "Provision platform credential"
    }

    private func endOperation() {
        refreshTimer?.invalidate()
        refreshTimer = nil
        refreshStartedAt = nil
        statusLabel.isHidden = true
        refreshButton.isEnabled = true
        provisionButton.isEnabled = true
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

    @objc private func provision() {
        onProvision?(platformCredentialProvisioned)
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
        for inventory in slotInventories {
            lines.append("")
            lines.append("Slot \(inventory.slot): \(inventory.description)")
            lines.append("Token: \(inventory.tokenLabel)")
            lines.append("Serial: \(inventory.serial)")
            lines.append(contentsOf: inventory.objects.lines)
            if inventory.isYubiHsm {
                lines.append(contentsOf: authenticatedObjectInventory(slot: inventory.slot))
            }
        }

        return lines.joined(separator: "\n")
    }

    func provisionPhone(configuration: ConnectorConfiguration) -> String {
        let initialize = initialize(configuration: configuration)
        guard initialize == CKR_OK else {
            return "C_Initialize failed: \(initialize)"
        }

        let discovery = yubiHsmTargets()
        if let error = discovery.error {
            return error
        }
        let targets = discovery.targets
        guard !targets.isEmpty else {
            return "No YubiHSM target is present."
        }

        var lines = [
            "Provision this iPhone for YubiHSM login",
            "Credential: \(platformCredentialName)",
            String(format: "Authentication Key: %04llX", UInt64(platformAuthenticationKeyID)),
            "",
        ]
        for (slot, target) in targets {
            lines.append(contentsOf: provisionTarget(slot: slot, name: target))
        }
        return lines.joined(separator: "\n")
    }

    func unprovisionPhone(configuration: ConnectorConfiguration) -> String {
        let initialize = initialize(configuration: configuration)
        guard initialize == CKR_OK else {
            return "C_Initialize failed: \(initialize)"
        }

        let discovery = yubiHsmTargets()
        if let error = discovery.error {
            return error
        }
        let targets = discovery.targets
        guard !targets.isEmpty else {
            return "No YubiHSM target is present; the platform credential was retained."
        }

        var lines = [
            "Unprovision this iPhone from YubiHSM login",
            "Credential: \(platformCredentialName)",
            String(format: "Authentication Key: %04llX", UInt64(platformAuthenticationKeyID)),
            "",
        ]
        var allSucceeded = true
        for (slot, target) in targets {
            let outcome = unprovisionTarget(slot: slot, name: target)
            lines.append(outcome.report)
            allSucceeded = allSucceeded && outcome.succeeded
        }
        guard allSucceeded else {
            lines.append("")
            lines.append("The local platform credential was retained so unprovisioning can be retried.")
            return lines.joined(separator: "\n")
        }

        let deletion = Array(platformCredentialName.utf8).withUnsafeBufferPointer { credential in
            PKCS11RS_PlatformCredentialDelete(
                credential.baseAddress,
                CK_ULONG(credential.count)
            )
        }
        if deletion == CKR_OK || deletion == CKR_OBJECT_HANDLE_INVALID {
            lines.append("")
            lines.append("Local platform credential deleted.")
        } else {
            lines.append("")
            lines.append("Local credential deletion failed: \(deletion)")
        }
        return lines.joined(separator: "\n")
    }

    func platformCredentialExists() -> Bool {
        var publicKey = [UInt8](repeating: 0, count: 65)
        var publicKeyLength = CK_ULONG(publicKey.count)
        let result = Array(platformCredentialName.utf8).withUnsafeBufferPointer { credential in
            publicKey.withUnsafeMutableBufferPointer { publicKey in
                PKCS11RS_PlatformCredentialGetPublicKey(
                    credential.baseAddress,
                    CK_ULONG(credential.count),
                    publicKey.baseAddress,
                    &publicKeyLength
                )
            }
        }
        return result == CKR_OK
    }

    private func yubiHsmTargets() -> (
        targets: [(CK_SLOT_ID, String)],
        error: String?
    ) {
        var count = CK_ULONG()
        var result = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count)
        guard result == CKR_OK else {
            return ([], "C_GetSlotList(size) failed: \(result)")
        }
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        result = slots.withUnsafeMutableBufferPointer { buffer in
            C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
        }
        guard result == CKR_OK else {
            return ([], "C_GetSlotList failed: \(result)")
        }

        var targets = [(CK_SLOT_ID, String)]()
        for slot in slots.prefix(Int(count)) {
            var token = CK_TOKEN_INFO()
            if C_GetTokenInfo(slot, &token) == CKR_OK {
                let label = paddedString(token.label)
                if label.hasPrefix("YubiHSM #") {
                    targets.append((slot, label))
                }
            }
        }
        return (targets, nil)
    }

    private func provisionTarget(slot: CK_SLOT_ID, name: String) -> [String] {
        var session = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        var result = C_OpenSession(
            slot,
            CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
            nil,
            nil,
            &session
        )
        guard result == CKR_OK else {
            return ["\(name): open failed: \(result)"]
        }
        defer { _ = C_CloseSession(session) }

        var bootstrapUsername = Array(":*".utf8)
        var bootstrapPassword = Array(yubiHsmAuthPassword.utf8)
        result = bootstrapPassword.withUnsafeMutableBufferPointer { password in
            bootstrapUsername.withUnsafeMutableBufferPointer { username in
                C_LoginUser(
                    session,
                    CK_USER_TYPE(CKU_USER),
                    password.baseAddress,
                    CK_ULONG(password.count),
                    username.baseAddress,
                    CK_ULONG(username.count)
                )
            }
        }
        _ = bootstrapPassword.withUnsafeMutableBytes { bytes in
            bytes.initializeMemory(as: UInt8.self, repeating: 0)
        }
        guard result == CKR_OK else {
            return ["\(name): bootstrap login failed: \(result)"]
        }

        var provisioningResult = CK_ULONG()
        let capabilities = platformCapabilities
        let delegatedCapabilities = platformCapabilities
        result = Array(platformCredentialName.utf8).withUnsafeBufferPointer { credential in
            Array(platformCredentialLabel.utf8).withUnsafeBufferPointer { label in
                capabilities.withUnsafeBufferPointer { capabilities in
                    delegatedCapabilities.withUnsafeBufferPointer { delegated in
                        PKCS11RS_YubiHsmProvisionPlatformCredential(
                            session,
                            credential.baseAddress,
                            CK_ULONG(credential.count),
                            platformAuthenticationKeyID,
                            label.baseAddress,
                            CK_ULONG(label.count),
                            platformDomains,
                            capabilities.baseAddress,
                            CK_ULONG(capabilities.count),
                            delegated.baseAddress,
                            CK_ULONG(delegated.count),
                            &provisioningResult
                        )
                    }
                }
            }
        }
        guard result == CKR_OK else {
            _ = C_Logout(session)
            return ["\(name): provisioning failed: \(result)"]
        }
        let action = switch provisioningResult {
        case CK_ULONG(PKCS11RS_PLATFORM_PROVISIONED): "provisioned"
        case CK_ULONG(PKCS11RS_PLATFORM_ALREADY_PROVISIONED): "already provisioned"
        case CK_ULONG(PKCS11RS_PLATFORM_REPAIRED): "repaired"
        default: "provisioned (unknown result \(provisioningResult))"
        }
        let logout = C_Logout(session)
        guard logout == CKR_OK else {
            return ["\(name): \(action), bootstrap logout failed: \(logout)"]
        }

        var platformUsername = Array(
            String(format: ":%04llX@%@", UInt64(platformAuthenticationKeyID), platformCredentialName)
                .utf8
        )
        result = platformUsername.withUnsafeMutableBufferPointer { username in
            C_LoginUser(
                session,
                CK_USER_TYPE(CKU_USER),
                nil,
                0,
                username.baseAddress,
                CK_ULONG(username.count)
            )
        }
        guard result == CKR_OK else {
            return ["\(name): \(action), platform login failed: \(result)"]
        }
        var random = UInt8()
        let verification = C_GenerateRandom(session, &random, 1)
        _ = C_Logout(session)
        guard verification == CKR_OK else {
            return ["\(name): \(action), authenticated verification failed: \(verification)"]
        }
        return ["\(name): \(action), login verified"]
    }

    private func unprovisionTarget(slot: CK_SLOT_ID, name: String) -> (
        report: String,
        succeeded: Bool
    ) {
        var session = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        var result = C_OpenSession(
            slot,
            CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
            nil,
            nil,
            &session
        )
        guard result == CKR_OK else {
            return ("\(name): open failed: \(result)", false)
        }
        defer { _ = C_CloseSession(session) }

        var bootstrapUsername = Array(":*".utf8)
        var bootstrapPassword = Array(yubiHsmAuthPassword.utf8)
        result = bootstrapPassword.withUnsafeMutableBufferPointer { password in
            bootstrapUsername.withUnsafeMutableBufferPointer { username in
                C_LoginUser(
                    session,
                    CK_USER_TYPE(CKU_USER),
                    password.baseAddress,
                    CK_ULONG(password.count),
                    username.baseAddress,
                    CK_ULONG(username.count)
                )
            }
        }
        _ = bootstrapPassword.withUnsafeMutableBytes { bytes in
            bytes.initializeMemory(as: UInt8.self, repeating: 0)
        }
        guard result == CKR_OK else {
            return ("\(name): bootstrap login failed: \(result)", false)
        }

        result = Array(platformCredentialName.utf8).withUnsafeBufferPointer { credential in
            PKCS11RS_YubiHsmUnprovisionPlatformCredential(
                session,
                credential.baseAddress,
                CK_ULONG(credential.count),
                platformAuthenticationKeyID
            )
        }
        let logout = C_Logout(session)
        guard result == CKR_OK else {
            return ("\(name): unprovisioning failed: \(result)", false)
        }
        guard logout == CKR_OK else {
            return ("\(name): unprovisioned, logout failed: \(logout)", false)
        }
        return ("\(name): unprovisioned", true)
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
        controller.onProvision = { [weak self] provisioned in
            self?.setPlatformCredentialProvisioned(!provisioned)
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
            let provisioned = moduleInspector.platformCredentialExists()
            DispatchQueue.main.async {
                self.controller.showInventory(result)
                self.controller.setPlatformCredentialProvisioned(provisioned)
            }
        }
    }

    private func initializeModule() {
        let configuration = connectorConfiguration()
        controller.beginRefresh()
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = moduleInspector.initializeAndDescribe(configuration: configuration)
            let provisioned = moduleInspector.platformCredentialExists()
            DispatchQueue.main.async {
                self.controller.showInventory(result)
                self.controller.setPlatformCredentialProvisioned(provisioned)
            }
        }
    }

    private func setPlatformCredentialProvisioned(_ provision: Bool) {
        let configuration = connectorConfiguration()
        controller.beginRefresh()
        inspectionQueue.async { [weak self] in
            guard let self else { return }
            let result = provision
                ? moduleInspector.provisionPhone(configuration: configuration)
                : moduleInspector.unprovisionPhone(configuration: configuration)
            let provisioned = moduleInspector.platformCredentialExists()
            DispatchQueue.main.async {
                self.controller.showInventory(result)
                self.controller.setPlatformCredentialProvisioned(provisioned)
            }
        }
    }
}
