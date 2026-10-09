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
private let postQuantumMlDsaLabel = "iPhone smoke ML-DSA-87"
private let postQuantumMlKemLabel = "iPhone smoke ML-KEM-1024"
private let postQuantumHybridKemLabel = "iPhone smoke MLKEM768-X25519"
private let postQuantumMessageLength = 32
private let postQuantumSecretLength = 32
private let previewSignRegistrationLabel = "iPhone smoke previewSign registration"
private let previewSignDerivedKeyLabel = "iPhone smoke previewSign ARKG-P256"
private let previewSignRegistrationID = Array("iphone-smoke-preview-sign-registration".utf8)
private let previewSignDerivedKeyID = Array("iphone-smoke-preview-sign-p256".utf8)
private let previewSignDerivationContext = Array("pkcs11rs iPhone previewSign smoke".utf8)
private let ckmPreviewSignKeyPairGen =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0001)
private let ckmPreviewSignDerive =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0002)
private let ckmPreviewSign =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0003)
private let ckmProjectPublicKey =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0004)
private let ckmMlKem768X25519KeyPairGen =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0012)
private let ckmMlKem768X25519 =
    CK_MECHANISM_TYPE(CKM_VENDOR_DEFINED) | CK_MECHANISM_TYPE(0x5053_0013)
private let ckkMlKem768X25519 =
    CK_KEY_TYPE(CKK_VENDOR_DEFINED) | CK_KEY_TYPE(0x5053_0011)
private let ckkPreviewSignRegistration =
    CK_KEY_TYPE(CKK_VENDOR_DEFINED) | CK_KEY_TYPE(0x5053_0001)
private let ckaPreviewSignRegistration =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5053_0001)
private let ckkYubicoHsmAuthSymmetric =
    CK_KEY_TYPE(CKK_VENDOR_DEFINED) | CK_KEY_TYPE(0x59554200) | CK_KEY_TYPE(38)
private let ckkYubicoHsmAuthAsymmetric =
    CK_KEY_TYPE(CKK_VENDOR_DEFINED) | CK_KEY_TYPE(0x59554200) | CK_KEY_TYPE(39)
private let ckaYubicoHsmAuthRetries =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5902)
private let ckaYubicoHsmAuthTouchRequired =
    CK_ATTRIBUTE_TYPE(CKA_VENDOR_DEFINED) | CK_ATTRIBUTE_TYPE(0x5903)
private struct ObjectInventory {
    var lines: [String]
}

private struct SlotInventory {
    let slot: CK_SLOT_ID
    let description: String
    let tokenLabel: String
    let serial: String
    let isYubiHsm: Bool
}

private struct AuthorizedSession {
    let session: CK_SESSION_HANDLE
}

private struct SourceLogin {
    let authorization: AuthorizedSession?
    let result: CK_RV
}

private struct YubiHsmLogin {
    let session: CK_SESSION_HANDLE?
    let result: CK_RV
    let credential: String?
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
        "platform": ["enabled": true],
        "yubihsm": [
            "urls": [url],
            "public_discovery": "0001password",
        ],
        "nfc": [
            "discovery": true,
        ],
        "ccid": [
            "secure_channel": "scp11b",
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

private func returnValueDescription(_ value: CK_RV) -> String {
    let code = String(format: "0x%llx", UInt64(value))
    guard let name = PKCS11RS_GetReturnValueName(value) else {
        return code
    }
    return "\(String(cString: name)) (\(code))"
}

private func userTypeDescription(_ userType: CK_USER_TYPE) -> String {
    switch userType {
    case CK_USER_TYPE(CKU_SO): "CKU_SO"
    case CK_USER_TYPE(CKU_USER): "CKU_USER"
    case CK_USER_TYPE(CKU_CONTEXT_SPECIFIC): "CKU_CONTEXT_SPECIFIC"
    default: "CK_USER_TYPE(\(userType))"
    }
}

private func sessionStateDescription(_ state: CK_STATE) -> String {
    let name: String
    switch state {
    case CK_STATE(CKS_RO_PUBLIC_SESSION): name = "CKS_RO_PUBLIC_SESSION"
    case CK_STATE(CKS_RO_USER_FUNCTIONS): name = "CKS_RO_USER_FUNCTIONS"
    case CK_STATE(CKS_RW_PUBLIC_SESSION): name = "CKS_RW_PUBLIC_SESSION"
    case CK_STATE(CKS_RW_USER_FUNCTIONS): name = "CKS_RW_USER_FUNCTIONS"
    case CK_STATE(CKS_RW_SO_FUNCTIONS): name = "CKS_RW_SO_FUNCTIONS"
    default: name = "CK_STATE"
    }
    return "\(name) (\(state))"
}

private func loginResultLine(_ userType: CK_USER_TYPE, result: CK_RV) -> String {
    "  C_Login(\(userTypeDescription(userType))) => \(returnValueDescription(result))"
}

private func loginUserResultLine(
    username: String,
    result: CK_RV,
    credential: String? = nil
) -> String {
    let suffix = credential.map { " using \($0)" } ?? ""
    return "  C_LoginUser(CKU_USER, \(username)) => \(returnValueDescription(result))\(suffix)"
}

private func isPivTokenLabel(_ tokenLabel: String) -> Bool {
    tokenLabel.hasPrefix("PIV #")
}

private func isFido2TokenLabel(_ tokenLabel: String) -> Bool {
    tokenLabel.hasPrefix("FIDO2 ")
}

private func isYubiHsmTokenLabel(_ tokenLabel: String) -> Bool {
    tokenLabel.hasPrefix("YubiHSM #")
}

private func isHostTokenLabel(_ tokenLabel: String) -> Bool {
    tokenLabel == "Secure Enclave"
}

private func authenticatedCredentialDescription(_ session: CK_SESSION_HANDLE) -> String {
    var length = CK_ULONG()
    var result = PKCS11RS_GetAuthenticatedCredential(session, nil, &length)
    guard result == CKR_OK else {
        return "<credential query failed: \(returnValueDescription(result))>"
    }
    var value = [UInt8](repeating: 0, count: Int(length))
    result = value.withUnsafeMutableBufferPointer { buffer in
        PKCS11RS_GetAuthenticatedCredential(session, buffer.baseAddress, &length)
    }
    guard result == CKR_OK else {
        return "<credential query failed: \(returnValueDescription(result))>"
    }
    return String(bytes: value.prefix(Int(length)), encoding: .utf8) ?? "<invalid UTF-8>"
}

private func authenticationDiagnostics(_ session: CK_SESSION_HANDLE) -> [String] {
    var length = CK_ULONG()
    var result = PKCS11RS_GetSecureChannel(session, nil, &length)
    var lines = [String]()
    if result == CKR_OK {
        var value = [UInt8](repeating: 0, count: Int(length))
        result = value.withUnsafeMutableBufferPointer {
            PKCS11RS_GetSecureChannel(session, $0.baseAddress, &length)
        }
        if result == CKR_OK {
            let channel = String(decoding: value.prefix(Int(length)), as: UTF8.self)
            lines.append("  Secure channel: \(channel)")
        }
    }
    if result != CKR_OK {
        lines.append("  Secure channel query failed: \(returnValueDescription(result))")
    }
    lines.append("  Credential: \(authenticatedCredentialDescription(session))")
    return lines
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
    object: CK_OBJECT_HANDLE
) -> String {
    var objectClass = CK_OBJECT_CLASS()
    var keyType = CK_KEY_TYPE()
    var hsmAuthRetries = CK_ULONG()
    var hsmAuthTouchRequired = CK_BBOOL()
    var label = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var identifier = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var ecPoint = [UInt8](repeating: 0, count: objectAttributeBufferCapacity)
    var attributes = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 7)

    let result = withUnsafeMutablePointer(to: &objectClass) { objectClassPointer in
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
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
                                    attributes[4].type = ckaYubicoHsmAuthRetries
                                    attributes[4].pValue = UnsafeMutableRawPointer(retriesPointer)
                                    attributes[4].ulValueLen = CK_ULONG(MemoryLayout<CK_ULONG>.size)
                                    attributes[5].type = ckaYubicoHsmAuthTouchRequired
                                    attributes[5].pValue = UnsafeMutableRawPointer(touchPointer)
                                    attributes[5].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                                    attributes[6].type = CK_ATTRIBUTE_TYPE(CKA_EC_POINT)
                                    attributes[6].pValue = ecPointBuffer.baseAddress
                                    attributes[6].ulValueLen = CK_ULONG(ecPointBuffer.count)
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
    if let length = availableLength(
        attributes[1],
        capacity: objectAttributeBufferCapacity
    ) {
        let value = String(decoding: label.prefix(length), as: UTF8.self)
        if !value.isEmpty {
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
        parts.append("attributes failed: \(returnValueDescription(result))")
    }
    if attributes[4].ulValueLen == CK_ULONG(MemoryLayout<CK_ULONG>.size),
       attributes[5].ulValueLen == CK_ULONG(MemoryLayout<CK_BBOOL>.size)
    {
        let algorithmName: String? = switch keyType {
        case ckkYubicoHsmAuthSymmetric: "symmetric AES-128"
        case ckkYubicoHsmAuthAsymmetric: "asymmetric P-256"
        default: nil
        }
        if let algorithmName {
            parts.append("YubiHSM Auth \(algorithmName)")
            parts.append("retries=\(hsmAuthRetries)")
            parts.append(
                "touch=\(hsmAuthTouchRequired != CK_BBOOL(CK_FALSE))"
            )
        }
    }
    return parts.joined(separator: ", ")
}

private func objectInventory(
    session: CK_SESSION_HANDLE,
    title: String
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
                failure = "C_FindObjects failed: \(returnValueDescription(findResult))"
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
            failure = "C_FindObjectsFinal failed: \(returnValueDescription(findFinalResult))"
        }
    } else {
        failure = "C_FindObjectsInit failed: \(returnValueDescription(findInitResult))"
    }

    let descriptions = objects.map { objectDescription(session: session, object: $0) }
    var lines = ["", "\(title): \(objects.count)"]
    lines.append(contentsOf: descriptions)
    if let failure {
        lines.append("  \(failure)")
    }
    return ObjectInventory(lines: lines)
}

private func findKey(
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

private func findObject(
    session: CK_SESSION_HANDLE,
    identifier: [UInt8]
) -> (result: CK_RV, object: CK_OBJECT_HANDLE?) {
    var identifier = identifier
    var attribute = CK_ATTRIBUTE()
    let initialize = identifier.withUnsafeMutableBytes { identifierBuffer in
        attribute.type = CK_ATTRIBUTE_TYPE(CKA_ID)
        attribute.pValue = identifierBuffer.baseAddress
        attribute.ulValueLen = CK_ULONG(identifierBuffer.count)
        return C_FindObjectsInit(session, &attribute, 1)
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

private func deleteObjects(
    session: CK_SESSION_HANDLE,
    identifier: [UInt8]
) -> (result: CK_RV, count: Int) {
    var deleted = 0
    while true {
        let found = findObject(session: session, identifier: identifier)
        guard found.result == CKR_OK else {
            return (found.result, deleted)
        }
        guard let object = found.object else {
            return (CK_RV(CKR_OK), deleted)
        }
        let result = C_DestroyObject(session, object)
        guard result == CKR_OK else {
            return (result, deleted)
        }
        deleted += 1
    }
}

private func generatePostQuantumKeyPair(
    session: CK_SESSION_HANDLE,
    mechanismType: CK_MECHANISM_TYPE,
    parameterSet: CK_ULONG?,
    label: String,
    identifier: [UInt8],
    publicUsageAttribute: CK_ATTRIBUTE_TYPE,
    privateUsageAttribute: CK_ATTRIBUTE_TYPE
) -> (result: CK_RV, publicKey: CK_OBJECT_HANDLE, privateKey: CK_OBJECT_HANDLE) {
    var token = CK_BBOOL(CK_TRUE)
    var publicUsage = CK_BBOOL(CK_TRUE)
    var privateUsage = CK_BBOOL(CK_TRUE)
    let hasParameterSet = parameterSet != nil
    var parameterSetValue = parameterSet ?? 0
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
                withUnsafeMutablePointer(to: &parameterSetValue) { parameterSetPointer in
                    identifier.withUnsafeMutableBytes { identifierBuffer in
                        label.withUnsafeMutableBytes { labelBuffer in
                            var publicAttributes = [CK_ATTRIBUTE](
                                repeating: CK_ATTRIBUTE(),
                                count: hasParameterSet ? 5 : 4
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
                            let usageIndex: Int
                            if hasParameterSet {
                                publicAttributes[3].type = CK_ATTRIBUTE_TYPE(CKA_PARAMETER_SET)
                                publicAttributes[3].pValue = UnsafeMutableRawPointer(parameterSetPointer)
                                publicAttributes[3].ulValueLen = CK_ULONG(
                                    MemoryLayout<CK_ULONG>.size
                                )
                                usageIndex = 4
                            } else {
                                usageIndex = 3
                            }
                            publicAttributes[usageIndex].type = publicUsageAttribute
                            publicAttributes[usageIndex].pValue = UnsafeMutableRawPointer(publicUsagePointer)
                            publicAttributes[usageIndex].ulValueLen = CK_ULONG(MemoryLayout<CK_BBOOL>.size)

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

private func exerciseMlDsa(
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
    var message = [UInt8](repeating: 0, count: postQuantumMessageLength)
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

private func attributeValue(
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

private func createPreviewSignRegistration(
    session: CK_SESSION_HANDLE
) -> (result: CK_RV, registration: [UInt8]?) {
    var mechanism = CK_MECHANISM(
        mechanism: ckmPreviewSignKeyPairGen,
        pParameter: nil,
        ulParameterLen: 0
    )
    var keyType = CK_KEY_TYPE(CKK_EC)
    var token = CK_BBOOL(CK_TRUE)
    var privateValue = CK_BBOOL(CK_TRUE)
    var label = Array(previewSignRegistrationLabel.utf8)
    var identifier = previewSignRegistrationID
    var publicKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var privateKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    let result = withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
        withUnsafeMutablePointer(to: &token) { tokenPointer in
            withUnsafeMutablePointer(to: &privateValue) { privatePointer in
                label.withUnsafeMutableBytes { labelBuffer in
                    identifier.withUnsafeMutableBytes { identifierBuffer in
                        var publicAttributes = [CK_ATTRIBUTE](repeating: CK_ATTRIBUTE(), count: 4)
                        publicAttributes[0] = CK_ATTRIBUTE(
                            type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE),
                            pValue: UnsafeMutableRawPointer(keyTypePointer),
                            ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)
                        )
                        publicAttributes[1] = CK_ATTRIBUTE(
                            type: CK_ATTRIBUTE_TYPE(CKA_TOKEN),
                            pValue: UnsafeMutableRawPointer(tokenPointer),
                            ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                        )
                        publicAttributes[2] = CK_ATTRIBUTE(
                            type: CK_ATTRIBUTE_TYPE(CKA_LABEL),
                            pValue: labelBuffer.baseAddress,
                            ulValueLen: CK_ULONG(labelBuffer.count)
                        )
                        publicAttributes[3] = CK_ATTRIBUTE(
                            type: CK_ATTRIBUTE_TYPE(CKA_ID),
                            pValue: identifierBuffer.baseAddress,
                            ulValueLen: CK_ULONG(identifierBuffer.count)
                        )
                        var privateAttributes = publicAttributes
                        privateAttributes.append(CK_ATTRIBUTE(
                            type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE),
                            pValue: UnsafeMutableRawPointer(privatePointer),
                            ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)
                        ))
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
    guard result == CKR_OK else { return (result, nil) }
    let registration = attributeValue(
        session: session,
        object: privateKey,
        type: ckaPreviewSignRegistration
    )
    return (registration.result, registration.value)
}

private func importPreviewSignRegistration(
    session: CK_SESSION_HANDLE,
    registration: [UInt8]
) -> (result: CK_RV, key: CK_OBJECT_HANDLE) {
    var objectClass = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
    var keyType = ckkPreviewSignRegistration
    var token = CK_BBOOL(CK_TRUE)
    var privateValue = CK_BBOOL(CK_TRUE)
    var derive = CK_BBOOL(CK_TRUE)
    var label = Array(previewSignRegistrationLabel.utf8)
    var identifier = previewSignRegistrationID
    var registration = registration
    var key = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    let result = withUnsafeMutablePointer(to: &objectClass) { classPointer in
        withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
            withUnsafeMutablePointer(to: &token) { tokenPointer in
                withUnsafeMutablePointer(to: &privateValue) { privatePointer in
                    withUnsafeMutablePointer(to: &derive) { derivePointer in
                        label.withUnsafeMutableBytes { labelBuffer in
                            identifier.withUnsafeMutableBytes { identifierBuffer in
                                registration.withUnsafeMutableBytes { registrationBuffer in
                                    var attributes = [
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: UnsafeMutableRawPointer(classPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: UnsafeMutableRawPointer(keyTypePointer), ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: UnsafeMutableRawPointer(tokenPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: UnsafeMutableRawPointer(privatePointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DERIVE), pValue: UnsafeMutableRawPointer(derivePointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_LABEL), pValue: labelBuffer.baseAddress, ulValueLen: CK_ULONG(labelBuffer.count)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: identifierBuffer.baseAddress, ulValueLen: CK_ULONG(identifierBuffer.count)),
                                        CK_ATTRIBUTE(type: ckaPreviewSignRegistration, pValue: registrationBuffer.baseAddress, ulValueLen: CK_ULONG(registrationBuffer.count)),
                                    ]
                                    return attributes.withUnsafeMutableBufferPointer { buffer in
                                        C_CreateObject(
                                            session,
                                            buffer.baseAddress,
                                            CK_ULONG(buffer.count),
                                            &key
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
    return (result, key)
}

private func derivePreviewSignKey(
    session: CK_SESSION_HANDLE,
    registrationKey: CK_OBJECT_HANDLE
) -> (result: CK_RV, key: CK_OBJECT_HANDLE) {
    var context = previewSignDerivationContext
    var objectClass = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
    var keyType = CK_KEY_TYPE(CKK_EC)
    var token = CK_BBOOL(CK_TRUE)
    var privateValue = CK_BBOOL(CK_TRUE)
    var sign = CK_BBOOL(CK_TRUE)
    var label = Array(previewSignDerivedKeyLabel.utf8)
    var identifier = previewSignDerivedKeyID
    var key = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    let result = context.withUnsafeMutableBytes { contextBuffer in
        var mechanism = CK_MECHANISM(
            mechanism: ckmPreviewSignDerive,
            pParameter: contextBuffer.baseAddress,
            ulParameterLen: CK_ULONG(contextBuffer.count)
        )
        return withUnsafeMutablePointer(to: &objectClass) { classPointer in
            withUnsafeMutablePointer(to: &keyType) { keyTypePointer in
                withUnsafeMutablePointer(to: &token) { tokenPointer in
                    withUnsafeMutablePointer(to: &privateValue) { privatePointer in
                        withUnsafeMutablePointer(to: &sign) { signPointer in
                            label.withUnsafeMutableBytes { labelBuffer in
                                identifier.withUnsafeMutableBytes { identifierBuffer in
                                    var attributes = [
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: UnsafeMutableRawPointer(classPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: UnsafeMutableRawPointer(keyTypePointer), ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: UnsafeMutableRawPointer(tokenPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: UnsafeMutableRawPointer(privatePointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: UnsafeMutableRawPointer(signPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_LABEL), pValue: labelBuffer.baseAddress, ulValueLen: CK_ULONG(labelBuffer.count)),
                                        CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: identifierBuffer.baseAddress, ulValueLen: CK_ULONG(identifierBuffer.count)),
                                    ]
                                    return attributes.withUnsafeMutableBufferPointer { buffer in
                                        C_DeriveKey(
                                            session,
                                            &mechanism,
                                            registrationKey,
                                            buffer.baseAddress,
                                            CK_ULONG(buffer.count),
                                            &key
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
    return (result, key)
}

private func resolvePreviewSignKey(
    session: CK_SESSION_HANDLE
) -> (result: CK_RV, key: CK_OBJECT_HANDLE, created: Bool, operation: String) {
    let existing = findKey(
        session: session,
        objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
        keyType: CK_KEY_TYPE(CKK_EC),
        identifier: previewSignDerivedKeyID
    )
    guard existing.result == CKR_OK else {
        return (existing.result, CK_OBJECT_HANDLE(CK_INVALID_HANDLE), false, "find derived key")
    }
    if let key = existing.object {
        return (CK_RV(CKR_OK), key, false, "reused persisted chain")
    }

    let existingRegistration = findKey(
        session: session,
        objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
        keyType: ckkPreviewSignRegistration,
        identifier: previewSignRegistrationID
    )
    guard existingRegistration.result == CKR_OK else {
        return (existingRegistration.result, CK_OBJECT_HANDLE(CK_INVALID_HANDLE), false, "find registration")
    }
    var registrationKey = existingRegistration.object
    if registrationKey == nil {
        let registration = createPreviewSignRegistration(session: session)
        guard registration.result == CKR_OK, let value = registration.registration else {
            return (registration.result, CK_OBJECT_HANDLE(CK_INVALID_HANDLE), false, "register credential")
        }
        let imported = importPreviewSignRegistration(session: session, registration: value)
        guard imported.result == CKR_OK else {
            return (imported.result, CK_OBJECT_HANDLE(CK_INVALID_HANDLE), false, "persist registration")
        }
        registrationKey = imported.key
    }
    let derived = derivePreviewSignKey(session: session, registrationKey: registrationKey!)
    guard derived.result == CKR_OK else {
        return (derived.result, CK_OBJECT_HANDLE(CK_INVALID_HANDLE), false, "derive P-256 key")
    }
    return (CK_RV(CKR_OK), derived.key, true, "created and persisted chain")
}

private func exercisePreviewSign(
    session: CK_SESSION_HANDLE,
    signingKey: CK_OBJECT_HANDLE,
    lines: inout [String],
    login: (CK_SESSION_HANDLE, CK_USER_TYPE) -> CK_RV
) -> (result: CK_RV, operation: String, signatureLength: Int, milliseconds: Double) {
    var project = CK_MECHANISM(
        mechanism: ckmProjectPublicKey,
        pParameter: nil,
        ulParameterLen: 0
    )
    var token = CK_BBOOL(CK_FALSE)
    var verify = CK_BBOOL(CK_TRUE)
    var projectedKey = CK_OBJECT_HANDLE(CK_INVALID_HANDLE)
    var result = withUnsafeMutablePointer(to: &token) { tokenPointer in
        withUnsafeMutablePointer(to: &verify) { verifyPointer in
            var attributes = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: UnsafeMutableRawPointer(tokenPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: UnsafeMutableRawPointer(verifyPointer), ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            ]
            return attributes.withUnsafeMutableBufferPointer { buffer in
                C_DeriveKey(
                    session,
                    &project,
                    signingKey,
                    buffer.baseAddress,
                    CK_ULONG(buffer.count),
                    &projectedKey
                )
            }
        }
    }
    guard result == CKR_OK else { return (result, "project public key", 0, 0) }
    defer { _ = C_DestroyObject(session, projectedKey) }

    var digest = [UInt8](repeating: 0, count: 32)
    result = digest.withUnsafeMutableBufferPointer { buffer in
        C_GenerateRandom(session, buffer.baseAddress, CK_ULONG(buffer.count))
    }
    guard result == CKR_OK else { return (result, "C_GenerateRandom", 0, 0) }

    var signMechanism = CK_MECHANISM(
        mechanism: ckmPreviewSign,
        pParameter: nil,
        ulParameterLen: 0
    )
    let started = ProcessInfo.processInfo.systemUptime
    result = C_SignInit(session, &signMechanism, signingKey)
    guard result == CKR_OK else { return (result, "C_SignInit(previewSign)", 0, 0) }
    result = login(session, CK_USER_TYPE(CKU_CONTEXT_SPECIFIC))
    lines.append(loginResultLine(CK_USER_TYPE(CKU_CONTEXT_SPECIFIC), result: result))
    lines.append(contentsOf: authenticationDiagnostics(session))
    guard result == CKR_OK else { return (result, "C_Login(CKU_CONTEXT_SPECIFIC)", 0, 0) }
    var signatureLength = CK_ULONG()
    result = digest.withUnsafeMutableBufferPointer { buffer in
        C_Sign(session, buffer.baseAddress, CK_ULONG(buffer.count), nil, &signatureLength)
    }
    guard result == CKR_OK else { return (result, "C_Sign(size)", 0, 0) }
    var signature = [UInt8](repeating: 0, count: Int(signatureLength))
    result = digest.withUnsafeMutableBufferPointer { digestBuffer in
        signature.withUnsafeMutableBufferPointer { signatureBuffer in
            C_Sign(
                session,
                digestBuffer.baseAddress,
                CK_ULONG(digestBuffer.count),
                signatureBuffer.baseAddress,
                &signatureLength
            )
        }
    }
    guard result == CKR_OK else { return (result, "C_Sign(previewSign)", 0, 0) }

    var verifyMechanism = CK_MECHANISM(
        mechanism: CK_MECHANISM_TYPE(CKM_ECDSA),
        pParameter: nil,
        ulParameterLen: 0
    )
    result = C_VerifyInit(session, &verifyMechanism, projectedKey)
    guard result == CKR_OK else { return (result, "C_VerifyInit(ECDSA)", signature.count, 0) }
    let signatureCount = signature.count
    result = digest.withUnsafeMutableBufferPointer { digestBuffer in
        signature.withUnsafeMutableBufferPointer { signatureBuffer in
            C_Verify(
                session,
                digestBuffer.baseAddress,
                CK_ULONG(digestBuffer.count),
                signatureBuffer.baseAddress,
                CK_ULONG(signatureCount)
            )
        }
    }
    let milliseconds = (ProcessInfo.processInfo.systemUptime - started) * 1_000
    return (result, "C_Verify(ECDSA)", signature.count, milliseconds)
}

// Explicit test-device credential, supplied anew and erased after each login.
// The physical smoke-test YubiKey must already have FIDO2 PIN 123456.
private func smokeFidoLogin(session: CK_SESSION_HANDLE, user: CK_USER_TYPE) -> CK_RV {
    var pin = Array("123456".utf8)
    defer {
        _ = pin.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
    return pin.withUnsafeMutableBufferPointer {
        C_Login(session, user, $0.baseAddress, CK_ULONG($0.count))
    }
}

private func hasPreviewSignSupport(_ slot: CK_SLOT_ID) -> Bool {
    [(ckmPreviewSignKeyPairGen, CK_FLAGS(CKF_GENERATE_KEY_PAIR)),
     (ckmPreviewSignDerive, CK_FLAGS(CKF_DERIVE)),
     (ckmPreviewSign, CK_FLAGS(CKF_SIGN))].allSatisfy { mechanism, flags in
        var information = CK_MECHANISM_INFO()
        return C_GetMechanismInfo(slot, mechanism, &information) == CKR_OK
            && information.flags & flags == flags
    }
}

private func fidoPreviewSignSmoke(
    slot: CK_SLOT_ID,
    login: (CK_SESSION_HANDLE, CK_USER_TYPE) -> CK_RV
) -> [String] {
    var lines = ["", "FIDO previewSign ARKG-P256:"]
    var session = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
    let open = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
        nil,
        nil,
        &session
    )
    guard open == CKR_OK else {
        return lines + ["  open failed: \(returnValueDescription(open))"]
    }
    defer { _ = C_CloseSession(session) }
    let result = login(session, CK_USER_TYPE(CKU_USER))
    lines.append(loginResultLine(CK_USER_TYPE(CKU_USER), result: result))
    lines.append(contentsOf: authenticationDiagnostics(session))
    guard result == CKR_OK || result == CKR_USER_ALREADY_LOGGED_IN else {
        return lines + ["  user login failed"]
    }
    defer { _ = C_Logout(session) }

    let resolved = resolvePreviewSignKey(session: session)
    guard resolved.result == CKR_OK else {
        return lines + [
            "  \(resolved.operation) failed: \(returnValueDescription(resolved.result))",
        ]
    }
    lines.append("  \(resolved.operation)")
    let exercised = exercisePreviewSign(
        session: session,
        signingKey: resolved.key,
        lines: &lines,
        login: login
    )
    guard exercised.result == CKR_OK else {
        return lines + [
            "  \(exercised.operation) failed: \(returnValueDescription(exercised.result))",
        ]
    }
    lines.append(
        String(
            format: "  previewSign and ECDSA verification passed in %.3f ms (%d-byte signature)",
            exercised.milliseconds,
            exercised.signatureLength
        )
    )
    return lines
}

private func exerciseKem(
    session: CK_SESSION_HANDLE,
    publicKey: CK_OBJECT_HANDLE,
    privateKey: CK_OBJECT_HANDLE,
    mechanismType: CK_MECHANISM_TYPE,
    constructionName: String
) -> (
    result: CK_RV,
    operation: String,
    ciphertextLength: Int,
    encapsulateMilliseconds: Double,
    decapsulateMilliseconds: Double
) {
    var mechanism = CK_MECHANISM(
        mechanism: mechanismType,
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
    var valueLength = CK_ULONG(postQuantumSecretLength)
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

    let first = attributeValue(
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
    let second = attributeValue(
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
    guard firstValue.count == postQuantumSecretLength, firstValue == secondValue else {
        return (
            CK_RV(CKR_GENERAL_ERROR),
            "\(constructionName) shared-secret comparison",
            ciphertext.count,
            encapsulateMilliseconds,
            decapsulateMilliseconds
        )
    }
    return (
        CK_RV(CKR_OK),
        "\(constructionName) shared-secret comparison",
        ciphertext.count,
        encapsulateMilliseconds,
        decapsulateMilliseconds
    )
}

private struct PostQuantumSupport {
    let lines: [String]
    let mlDsa: Bool
    let mlKem: Bool
    let hybridKem: Bool

    var any: Bool { mlDsa || mlKem || hybridKem }
}

private struct PostQuantumPair {
    let result: CK_RV
    let publicKey: CK_OBJECT_HANDLE
    let privateKey: CK_OBJECT_HANDLE
    let status: String
}

private func mechanismList(
    slot: CK_SLOT_ID
) -> (result: CK_RV, mechanisms: [CK_MECHANISM_TYPE]) {
    var count = CK_ULONG()
    var result = C_GetMechanismList(slot, nil, &count)
    guard result == CKR_OK else {
        return (result, [])
    }
    var mechanisms = [CK_MECHANISM_TYPE](repeating: 0, count: Int(count))
    result = mechanisms.withUnsafeMutableBufferPointer { buffer in
        C_GetMechanismList(slot, buffer.baseAddress, &count)
    }
    while result == CKR_BUFFER_TOO_SMALL && Int(count) > mechanisms.count {
        mechanisms = [CK_MECHANISM_TYPE](repeating: 0, count: Int(count))
        result = mechanisms.withUnsafeMutableBufferPointer { buffer in
            C_GetMechanismList(slot, buffer.baseAddress, &count)
        }
    }
    guard result == CKR_OK else {
        return (result, [])
    }
    return (CK_RV(CKR_OK), Array(mechanisms.prefix(Int(count))))
}

private func mechanismRequirement(
    slot: CK_SLOT_ID,
    name: String,
    type: CK_MECHANISM_TYPE,
    advertised: Bool,
    requiredFlags: CK_FLAGS
) -> (supported: Bool, line: String) {
    guard advertised else {
        return (false, "  \(name): not advertised")
    }
    var information = CK_MECHANISM_INFO()
    let result = C_GetMechanismInfo(slot, type, &information)
    guard result == CKR_OK else {
        return (
            false,
            "  \(name): advertised, but C_GetMechanismInfo failed: \(returnValueDescription(result))"
        )
    }
    let missing = requiredFlags & ~information.flags
    let hardware = information.flags & CK_FLAGS(CKF_HW) != 0
    let flags = String(format: "0x%llX", UInt64(information.flags))
    let suffix = missing == 0
        ? "advertised, required flags present"
        : String(format: "advertised, missing flags 0x%llX", UInt64(missing))
    return (
        missing == 0,
        "  \(name): flags=\(flags), HW=\(hardware), key range \(information.ulMinKeySize)...\(information.ulMaxKeySize), \(suffix)"
    )
}

private func postQuantumSupport(slot: CK_SLOT_ID) -> PostQuantumSupport {
    let listed = mechanismList(slot: slot)
    guard listed.result == CKR_OK else {
        return PostQuantumSupport(
            lines: [
                "",
                "PQC mechanism report:",
                "  C_GetMechanismList failed: \(returnValueDescription(listed.result))",
            ],
            mlDsa: false,
            mlKem: false,
            hybridKem: false
        )
    }
    let mechanisms = Set(listed.mechanisms)
    let dsaGeneration = mechanismRequirement(
        slot: slot,
        name: "CKM_ML_DSA_KEY_PAIR_GEN",
        type: CK_MECHANISM_TYPE(CKM_ML_DSA_KEY_PAIR_GEN),
        advertised: mechanisms.contains(CK_MECHANISM_TYPE(CKM_ML_DSA_KEY_PAIR_GEN)),
        requiredFlags: CK_FLAGS(CKF_GENERATE_KEY_PAIR)
    )
    let dsa = mechanismRequirement(
        slot: slot,
        name: "CKM_ML_DSA",
        type: CK_MECHANISM_TYPE(CKM_ML_DSA),
        advertised: mechanisms.contains(CK_MECHANISM_TYPE(CKM_ML_DSA)),
        requiredFlags: CK_FLAGS(CKF_SIGN) | CK_FLAGS(CKF_VERIFY)
    )
    let kemGeneration = mechanismRequirement(
        slot: slot,
        name: "CKM_ML_KEM_KEY_PAIR_GEN",
        type: CK_MECHANISM_TYPE(CKM_ML_KEM_KEY_PAIR_GEN),
        advertised: mechanisms.contains(CK_MECHANISM_TYPE(CKM_ML_KEM_KEY_PAIR_GEN)),
        requiredFlags: CK_FLAGS(CKF_GENERATE_KEY_PAIR)
    )
    let kem = mechanismRequirement(
        slot: slot,
        name: "CKM_ML_KEM",
        type: CK_MECHANISM_TYPE(CKM_ML_KEM),
        advertised: mechanisms.contains(CK_MECHANISM_TYPE(CKM_ML_KEM)),
        requiredFlags: CK_FLAGS(CKF_ENCAPSULATE) | CK_FLAGS(CKF_DECAPSULATE)
    )
    let hybridGeneration = mechanismRequirement(
        slot: slot,
        name: "CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN",
        type: ckmMlKem768X25519KeyPairGen,
        advertised: mechanisms.contains(ckmMlKem768X25519KeyPairGen),
        requiredFlags: CK_FLAGS(CKF_GENERATE_KEY_PAIR)
    )
    let hybrid = mechanismRequirement(
        slot: slot,
        name: "CKM_PKCS11RS_MLKEM768_X25519",
        type: ckmMlKem768X25519,
        advertised: mechanisms.contains(ckmMlKem768X25519),
        requiredFlags: CK_FLAGS(CKF_ENCAPSULATE) | CK_FLAGS(CKF_DECAPSULATE)
    )
    return PostQuantumSupport(
        lines: [
            "",
            "PQC mechanism report:",
            dsaGeneration.line,
            dsa.line,
            kemGeneration.line,
            kem.line,
            hybridGeneration.line,
            hybrid.line,
        ],
        mlDsa: dsaGeneration.supported && dsa.supported,
        mlKem: kemGeneration.supported && kem.supported,
        hybridKem: hybridGeneration.supported && hybrid.supported
    )
}

private func postQuantumIdentifiers(
    tokenLabel: String
) -> (mlDsa: [UInt8], mlKem: [UInt8], hybridKem: [UInt8]) {
    if isPivTokenLabel(tokenLabel) {
        // PKCS #11 exposes PIV key references as compact CKA_ID values. The
        // first three retired key-management slots (raw PIV references 0x82,
        // 0x83, and 0x84) are therefore IDs 5, 6, and 7 at this API boundary.
        return ([5], [6], [7])
    }
    if isYubiHsmTokenLabel(tokenLabel) {
        return ([0x7e, 0x20], [0x7e, 0x21], [0x7e, 0x22])
    }
    return (
        Array("iphone-smoke-ml-dsa-87".utf8),
        Array("iphone-smoke-ml-kem-1024".utf8),
        Array("iphone-smoke-mlkem768-x25519".utf8)
    )
}

private func resolvePostQuantumPair(
    session: CK_SESSION_HANDLE,
    keyType: CK_KEY_TYPE,
    identifier: [UInt8],
    mechanismType: CK_MECHANISM_TYPE,
    parameterSet: CK_ULONG?,
    label: String,
    publicUsageAttribute: CK_ATTRIBUTE_TYPE,
    privateUsageAttribute: CK_ATTRIBUTE_TYPE,
    allowGeneration: Bool
) -> PostQuantumPair {
    let foundPublic = findKey(
        session: session,
        objectClass: CK_OBJECT_CLASS(CKO_PUBLIC_KEY),
        keyType: keyType,
        identifier: identifier
    )
    guard foundPublic.result == CKR_OK else {
        return PostQuantumPair(
            result: foundPublic.result,
            publicKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            privateKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            status: "public-key search failed"
        )
    }
    let foundPrivate = findKey(
        session: session,
        objectClass: CK_OBJECT_CLASS(CKO_PRIVATE_KEY),
        keyType: keyType,
        identifier: identifier
    )
    guard foundPrivate.result == CKR_OK else {
        return PostQuantumPair(
            result: foundPrivate.result,
            publicKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            privateKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            status: "private-key search failed"
        )
    }
    if let publicKey = foundPublic.object, let privateKey = foundPrivate.object {
        return PostQuantumPair(
            result: CK_RV(CKR_OK),
            publicKey: publicKey,
            privateKey: privateKey,
            status: "keypair already present"
        )
    }
    guard allowGeneration else {
        return PostQuantumPair(
            result: CK_RV(CKR_OBJECT_HANDLE_INVALID),
            publicKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            privateKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            status: "keypair missing after SO provisioning; USER phase will not generate"
        )
    }
    let cleared = deleteObjects(session: session, identifier: identifier)
    guard cleared.result == CKR_OK else {
        return PostQuantumPair(
            result: cleared.result,
            publicKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            privateKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            status: "failed to clear reserved identifier"
        )
    }

    let generationState = currentSessionState(session)
    guard generationState.result == CKR_OK else {
        return PostQuantumPair(
            result: generationState.result,
            publicKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            privateKey: CK_OBJECT_HANDLE(CK_INVALID_HANDLE),
            status: "C_GetSessionInfo before C_GenerateKeyPair failed"
        )
    }

    let started = ProcessInfo.processInfo.systemUptime
    let generated = generatePostQuantumKeyPair(
        session: session,
        mechanismType: mechanismType,
        parameterSet: parameterSet,
        label: label,
        identifier: identifier,
        publicUsageAttribute: publicUsageAttribute,
        privateUsageAttribute: privateUsageAttribute
    )
    let milliseconds = (ProcessInfo.processInfo.systemUptime - started) * 1_000
    return PostQuantumPair(
        result: generated.result,
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        status: generated.result == CKR_OK
            ? (cleared.count == 0
                ? String(format: "generated in %.3f ms", milliseconds)
                : String(
                    format: "replaced %d object(s), generated in %.3f ms",
                    cleared.count,
                    milliseconds
                ))
            : "C_GenerateKeyPair failed in \(sessionStateDescription(generationState.state))"
    )
}

private func exercisePostQuantumMechanisms(
    session: CK_SESSION_HANDLE,
    tokenLabel: String,
    support: PostQuantumSupport,
    performOperations: Bool = true,
    allowGeneration: Bool = true,
    reportPairStatus: Bool = true
) -> [String] {
    var lines = ["", "PQC functional smoke test:"]
    let identifiers = postQuantumIdentifiers(tokenLabel: tokenLabel)

    if support.mlDsa {
        let pair = resolvePostQuantumPair(
            session: session,
            keyType: CK_KEY_TYPE(CKK_ML_DSA),
            identifier: identifiers.mlDsa,
            mechanismType: CK_MECHANISM_TYPE(CKM_ML_DSA_KEY_PAIR_GEN),
            parameterSet: CK_ULONG(CKP_ML_DSA_87),
            label: postQuantumMlDsaLabel,
            publicUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_VERIFY),
            privateUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_SIGN),
            allowGeneration: allowGeneration
        )
        if pair.result == CKR_OK {
            if reportPairStatus {
                lines.append("  ML-DSA-87 \(pair.status)")
            }
            if performOperations {
                let exercised = exerciseMlDsa(
                    session: session,
                    publicKey: pair.publicKey,
                    privateKey: pair.privateKey
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
                    lines.append(
                        "  advertised ML-DSA failed at \(exercised.operation): \(returnValueDescription(exercised.result))"
                    )
                }
            }
        } else {
            lines.append(
                "  advertised ML-DSA failed: \(pair.status): \(returnValueDescription(pair.result))"
            )
        }
    } else {
        lines.append("  ML-DSA functional test skipped: required mechanism flags not advertised")
    }

    if support.mlKem {
        let pair = resolvePostQuantumPair(
            session: session,
            keyType: CK_KEY_TYPE(CKK_ML_KEM),
            identifier: identifiers.mlKem,
            mechanismType: CK_MECHANISM_TYPE(CKM_ML_KEM_KEY_PAIR_GEN),
            parameterSet: CK_ULONG(CKP_ML_KEM_1024),
            label: postQuantumMlKemLabel,
            publicUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_ENCAPSULATE),
            privateUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_DECAPSULATE),
            allowGeneration: allowGeneration
        )
        if pair.result == CKR_OK {
            if reportPairStatus {
                lines.append("  ML-KEM-1024 \(pair.status)")
            }
            if performOperations {
                let exercised = exerciseKem(
                    session: session,
                    publicKey: pair.publicKey,
                    privateKey: pair.privateKey,
                    mechanismType: CK_MECHANISM_TYPE(CKM_ML_KEM),
                    constructionName: "ML-KEM-1024"
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
                    lines.append(
                        "  advertised ML-KEM failed at \(exercised.operation): \(returnValueDescription(exercised.result))"
                    )
                }
            }
        } else {
            lines.append(
                "  advertised ML-KEM failed: \(pair.status): \(returnValueDescription(pair.result))"
            )
        }
    } else {
        lines.append("  ML-KEM functional test skipped: required mechanism flags not advertised")
    }

    if support.hybridKem {
        let pair = resolvePostQuantumPair(
            session: session,
            keyType: ckkMlKem768X25519,
            identifier: identifiers.hybridKem,
            mechanismType: ckmMlKem768X25519KeyPairGen,
            parameterSet: nil,
            label: postQuantumHybridKemLabel,
            publicUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_ENCAPSULATE),
            privateUsageAttribute: CK_ATTRIBUTE_TYPE(CKA_DECAPSULATE),
            allowGeneration: allowGeneration
        )
        if pair.result == CKR_OK {
            if reportPairStatus {
                lines.append("  MLKEM768-X25519 \(pair.status)")
            }
            if performOperations {
                let exercised = exerciseKem(
                    session: session,
                    publicKey: pair.publicKey,
                    privateKey: pair.privateKey,
                    mechanismType: ckmMlKem768X25519,
                    constructionName: "MLKEM768-X25519"
                )
                if exercised.result == CKR_OK {
                    lines.append(
                        String(
                            format: "  MLKEM768-X25519 encapsulate %.3f ms, decapsulate %.3f ms (%d-byte ciphertext, shared secret matched)",
                            exercised.encapsulateMilliseconds,
                            exercised.decapsulateMilliseconds,
                            exercised.ciphertextLength
                        )
                    )
                } else {
                    lines.append(
                        "  advertised MLKEM768-X25519 failed at \(exercised.operation): \(returnValueDescription(exercised.result))"
                    )
                }
            }
        } else {
            lines.append(
                "  advertised MLKEM768-X25519 failed: \(pair.status): \(returnValueDescription(pair.result))"
            )
        }
    } else {
        lines.append(
            "  MLKEM768-X25519 functional test skipped: required mechanism flags not advertised"
        )
    }
    return lines
}

private func currentSessionState(
    _ session: CK_SESSION_HANDLE
) -> (result: CK_RV, state: CK_STATE) {
    var information = CK_SESSION_INFO()
    let result = C_GetSessionInfo(session, &information)
    return (result, information.state)
}

private func unauthenticatedPostQuantumSmoke(
    slot: CK_SLOT_ID,
    tokenLabel: String,
    support: PostQuantumSupport
) -> [String] {
    guard support.any else { return [] }
    var session = CK_SESSION_HANDLE()
    let open = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
        nil,
        nil,
        &session
    )
    guard open == CKR_OK else {
        return [
            "",
            "PQC functional smoke test:",
            "  C_OpenSession(RW) failed: \(returnValueDescription(open))",
        ]
    }
    var lines = exercisePostQuantumMechanisms(
        session: session,
        tokenLabel: tokenLabel,
        support: support
    )
    let close = C_CloseSession(session)
    if close != CKR_OK {
        lines.append("  C_CloseSession failed: \(returnValueDescription(close))")
    }
    return lines
}

private func publicObjectInventory(
    slot: CK_SLOT_ID
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
            lines: ["", "Objects: C_OpenSession failed: \(returnValueDescription(openResult))"]
        )
    }

    var inventory = objectInventory(
        session: session,
        title: "Objects (public session)"
    )
    let closeResult = C_CloseSession(session)
    if closeResult != CKR_OK {
        inventory.lines.append("  C_CloseSession failed: \(returnValueDescription(closeResult))")
    }
    return inventory
}

private func yubiHsmLogin(
    slot: CK_SLOT_ID
) -> YubiHsmLogin {
    let usernameValue = "pkcs11:"
    var session = CK_SESSION_HANDLE()
    let openResult = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
        nil,
        nil,
        &session
    )
    guard openResult == CKR_OK else {
        return YubiHsmLogin(session: nil, result: openResult, credential: nil)
    }

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
    guard loginResult == CKR_OK || loginResult == CKR_USER_ALREADY_LOGGED_IN else {
        _ = C_CloseSession(session)
        return YubiHsmLogin(session: nil, result: loginResult, credential: nil)
    }
    return YubiHsmLogin(
        session: session,
        result: loginResult,
        credential: authenticatedCredentialDescription(session)
    )
}

private func loginSourceSlot(_ slot: CK_SLOT_ID) -> SourceLogin {
    var session = CK_SESSION_HANDLE()
    let openResult = C_OpenSession(
        slot,
        CK_FLAGS(CKF_SERIAL_SESSION),
        nil,
        nil,
        &session
    )
    guard openResult == CKR_OK else {
        return SourceLogin(authorization: nil, result: openResult)
    }

    let loginResult = C_Login(
        session,
        CK_USER_TYPE(CKU_USER),
        nil,
        0
    )
    guard loginResult == CKR_OK || loginResult == CKR_USER_ALREADY_LOGGED_IN else {
        _ = C_CloseSession(session)
        return SourceLogin(authorization: nil, result: loginResult)
    }
    return SourceLogin(
        authorization: AuthorizedSession(
            session: session
        ),
        result: loginResult
    )
}

private func hasHardwareSessionKeyDerivation(_ slot: CK_SLOT_ID) -> Bool {
    var information = CK_MECHANISM_INFO()
    return C_GetMechanismInfo(
        slot,
        CK_MECHANISM_TYPE(CKM_CONCATENATE_BASE_AND_KEY),
        &information
    ) == CKR_OK && information.flags & CK_FLAGS(CKF_HW) != 0
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
            return (nil, "C_Initialize failed: \(returnValueDescription(initialize))")
        }

        var info = CK_INFO()
        let getInfo = C_GetInfo(&info)
        guard getInfo == CKR_OK else {
            return (nil, "C_GetInfo failed: \(returnValueDescription(getInfo))")
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
            return "C_GetSlotList failed: \(returnValueDescription(listResult))"
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
                lines.append("Slot \(slot) query failed: \(returnValueDescription(slotResult))/\(returnValueDescription(tokenResult))")
                continue
            }
            let description = paddedString(slotInfo.slotDescription)
            let tokenLabel = paddedString(tokenInfo.label)
            let serial = paddedString(tokenInfo.serialNumber)
            slotInventories.append(SlotInventory(
                slot: slot,
                description: description,
                tokenLabel: tokenLabel,
                serial: serial,
                isYubiHsm: isYubiHsmTokenLabel(tokenLabel)
            ))
        }

        var authorizedSessions = [AuthorizedSession]()
        func appendSlotHeader(_ inventory: SlotInventory) {
            lines.append("")
            lines.append("Slot \(inventory.slot): \(inventory.description)")
            lines.append("Token: \(inventory.tokenLabel)")
            lines.append("Serial: \(inventory.serial)")
        }
        func appendPublicObjects(_ inventory: SlotInventory) {
            lines.append(contentsOf: publicObjectInventory(slot: inventory.slot).lines)
        }

        let yubiHsmInventories = slotInventories.filter(\.isYubiHsm)
        let nativeSessionKeyProviders = Set(yubiHsmInventories.compactMap {
            hasHardwareSessionKeyDerivation($0.slot) ? $0.slot : nil
        })
        let yubiHsmLoginOrder = yubiHsmInventories.filter {
            nativeSessionKeyProviders.contains($0.slot)
        } + yubiHsmInventories.filter {
            !nativeSessionKeyProviders.contains($0.slot)
        }

        // Render slots in the same dependency order in which they are used.
        // Successful source sessions remain open for later YubiHSM logins.
        for inventory in slotInventories where !inventory.isYubiHsm {
            appendSlotHeader(inventory)
            let support = postQuantumSupport(slot: inventory.slot)
            appendPublicObjects(inventory)
            lines.append(contentsOf: support.lines)
            if isFido2TokenLabel(inventory.tokenLabel) {
                if hasPreviewSignSupport(inventory.slot) {
                    lines.append(contentsOf: fidoPreviewSignSmoke(slot: inventory.slot, login: smokeFidoLogin))
                } else {
                    lines.append("  previewSign skipped: required mechanisms not advertised")
                }
            }
            var authenticatedSession: CK_SESSION_HANDLE?
            if isHostTokenLabel(inventory.tokenLabel) || inventory.tokenLabel.hasPrefix("Issuer SD #") {
                let source = loginSourceSlot(inventory.slot)
                lines.append("")
                lines.append(loginResultLine(CK_USER_TYPE(CKU_USER), result: source.result))
                if let authorization = source.authorization {
                    authorizedSessions.append(authorization)
                    authenticatedSession = authorization.session
                    lines.append(contentsOf: authenticationDiagnostics(authorization.session))
                }
            }
            if support.any {
                if let authenticatedSession {
                    lines.append(contentsOf: exercisePostQuantumMechanisms(
                        session: authenticatedSession,
                        tokenLabel: inventory.tokenLabel,
                        support: support
                    ))
                } else {
                    lines.append(contentsOf: unauthenticatedPostQuantumSmoke(
                        slot: inventory.slot,
                        tokenLabel: inventory.tokenLabel,
                        support: support
                    ))
                }
            }
            if let authenticatedSession {
                lines.append(contentsOf: objectInventory(
                    session: authenticatedSession,
                    title: "Objects (authenticated session)"
                ).lines)
            }
        }

        for inventory in yubiHsmLoginOrder {
            appendSlotHeader(inventory)
            appendPublicObjects(inventory)
            let support = postQuantumSupport(slot: inventory.slot)
            lines.append(contentsOf: support.lines)
            let login = yubiHsmLogin(slot: inventory.slot)
            if let session = login.session {
                authorizedSessions.append(AuthorizedSession(session: session))
                lines.append("")
                lines.append(loginUserResultLine(
                    username: "pkcs11:",
                    result: login.result
                ))
                lines.append(contentsOf: authenticationDiagnostics(session))
                if support.any {
                    lines.append(contentsOf: exercisePostQuantumMechanisms(
                        session: session,
                        tokenLabel: inventory.tokenLabel,
                        support: support
                    ))
                }
                lines.append(contentsOf: objectInventory(
                    session: session,
                    title: "Objects (authenticated session)"
                ).lines)
            } else {
                lines.append("")
                lines.append(loginUserResultLine(username: "pkcs11:", result: login.result))
                if support.any {
                    lines.append("  PQC functional test skipped because authentication failed")
                }
            }
        }

        var cleanupLines = [String]()
        for authorization in authorizedSessions.reversed() {
            let result = C_CloseSession(authorization.session)
            if result != CKR_OK {
                cleanupLines.append("C_CloseSession failed: \(returnValueDescription(result))")
            }
        }
        if !cleanupLines.isEmpty {
            lines.append("")
            lines.append("Credential session cleanup:")
            lines.append(contentsOf: cleanupLines.map { "  \($0)" })
        }

        return lines.joined(separator: "\n")
    }

    func provisionPhone(configuration: ConnectorConfiguration) -> String {
        let initialize = initialize(configuration: configuration)
        guard initialize == CKR_OK else {
            return "C_Initialize failed: \(returnValueDescription(initialize))"
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
            return "C_Initialize failed: \(returnValueDescription(initialize))"
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
            lines.append("Local credential deletion failed: \(returnValueDescription(deletion))")
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
            return ([], "C_GetSlotList(size) failed: \(returnValueDescription(result))")
        }
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        result = slots.withUnsafeMutableBufferPointer { buffer in
            C_GetSlotList(CK_BBOOL(CK_TRUE), buffer.baseAddress, &count)
        }
        guard result == CKR_OK else {
            return ([], "C_GetSlotList failed: \(returnValueDescription(result))")
        }

        var targets = [(CK_SLOT_ID, String)]()
        for slot in slots.prefix(Int(count)) {
            var token = CK_TOKEN_INFO()
            if C_GetTokenInfo(slot, &token) == CKR_OK {
                let label = paddedString(token.label)
                if isYubiHsmTokenLabel(label) {
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
            return ["\(name): open failed: \(returnValueDescription(result))"]
        }
        defer { _ = C_CloseSession(session) }

        var bootstrapUsername = Array("pkcs11:".utf8)
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
            return ["\(name): bootstrap login failed: \(returnValueDescription(result))"]
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
            return ["\(name): provisioning failed: \(returnValueDescription(result))"]
        }
        let action = switch provisioningResult {
        case CK_ULONG(PKCS11RS_PLATFORM_PROVISIONED): "provisioned"
        case CK_ULONG(PKCS11RS_PLATFORM_ALREADY_PROVISIONED): "already provisioned"
        case CK_ULONG(PKCS11RS_PLATFORM_REPAIRED): "repaired"
        default: "provisioned (unknown result \(provisioningResult))"
        }
        let logout = C_Logout(session)
        guard logout == CKR_OK else {
            return ["\(name): \(action), bootstrap logout failed: \(returnValueDescription(logout))"]
        }

        var platformUsername = Array("pkcs11:".utf8)
        var verificationPassword = Array(yubiHsmAuthPassword.utf8)
        result = verificationPassword.withUnsafeMutableBufferPointer { password in
            platformUsername.withUnsafeMutableBufferPointer { username in
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
        _ = verificationPassword.withUnsafeMutableBytes { bytes in
            bytes.initializeMemory(as: UInt8.self, repeating: 0)
        }
        guard result == CKR_OK else {
            return ["\(name): \(action), platform login failed: \(returnValueDescription(result))"]
        }
        var random = UInt8()
        let verification = C_GenerateRandom(session, &random, 1)
        _ = C_Logout(session)
        guard verification == CKR_OK else {
            return ["\(name): \(action), authenticated verification failed: \(returnValueDescription(verification))"]
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
            return ("\(name): open failed: \(returnValueDescription(result))", false)
        }
        defer { _ = C_CloseSession(session) }

        var bootstrapUsername = Array("pkcs11:".utf8)
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
            return ("\(name): bootstrap login failed: \(returnValueDescription(result))", false)
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
            return ("\(name): unprovisioning failed: \(returnValueDescription(result))", false)
        }
        guard logout == CKR_OK else {
            return ("\(name): unprovisioned, logout failed: \(returnValueDescription(logout))", false)
        }
        return ("\(name): unprovisioned", true)
    }

    func finalize() {
        if initialized {
            let result = C_Finalize(nil)
            if result == CKR_OK {
                initialized = false
            } else {
                print("C_Finalize failed: \(returnValueDescription(result))")
            }
        }
    }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
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
        controller.onRefresh = { [weak self] in
            self?.refresh()
        }
        controller.onProvision = { [weak self] provisioned in
            self?.setPlatformCredentialProvisioned(!provisioned)
        }
        return true
    }

    func connectWindow(to scene: UIWindowScene) -> UIWindow {
        let window = UIWindow(windowScene: scene)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        initializeModule()
        return window
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

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene,
              let appDelegate = UIApplication.shared.delegate as? AppDelegate else { return }
        window = appDelegate.connectWindow(to: windowScene)
    }
}
