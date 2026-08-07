import CryptoTokenKit
import Foundation
import PKCS11RS

final class SmartCardReaderRegistration {
    let name: String

    private let lock = NSLock()

    init(name: String) {
        self.name = name
    }

    func transmit(_ command: Data, timeoutMilliseconds: UInt64) -> (CK_RV, Data) {
        lock.lock()
        defer { lock.unlock() }

        guard
            let manager = TKSmartCardSlotManager.default,
            let slot = manager.slotNamed(name),
            let card = slot.makeSmartCard()
        else {
            return (CK_RV(CKR_DEVICE_REMOVED), Data())
        }

        let timeout = DispatchTime.now() + .milliseconds(
            Int(min(timeoutMilliseconds == 0 ? 30_000 : timeoutMilliseconds, UInt64(Int.max)))
        )
        let session = DispatchSemaphore(value: 0)
        var sessionOpened = false
        card.beginSession { success, _ in
            sessionOpened = success
            session.signal()
        }
        guard session.wait(timeout: timeout) == .success, sessionOpened else {
            return (CK_RV(CKR_DEVICE_ERROR), Data())
        }
        defer { card.endSession() }

        let transmitted = DispatchSemaphore(value: 0)
        var response: Data?
        card.transmit(command) { received, _ in
            response = received
            transmitted.signal()
        }
        guard transmitted.wait(timeout: timeout) == .success, let response else {
            return (CK_RV(CKR_DEVICE_ERROR), Data())
        }
        return (CK_RV(CKR_OK), response)
    }
}

final class SmartCardReaderDiscovery {
    private var retainedReaders = [String: SmartCardReaderRegistration]()

    func enumerate(
        sinkContext: UnsafeMutableRawPointer,
        addReader: PKCS11RS_ADD_CCID_READER
    ) -> CK_RV {
        guard let manager = TKSmartCardSlotManager.default else {
            return CK_RV(CKR_OK)
        }
        for slotName in manager.slotNames {
            guard let slot = manager.slotNamed(slotName) else {
                continue
            }
            let reader = retainedReaders[slotName] ?? SmartCardReaderRegistration(name: slotName)
            retainedReaders[slotName] = reader
            let name = Data(reader.name.utf8)
            let atr = slot.atr.map { Data($0.bytes) } ?? Data()
            let result = name.withUnsafeBytes { nameBytes in
                atr.withUnsafeBytes { atrBytes in
                    addReader(
                        sinkContext,
                        nameBytes.bindMemory(to: CK_UTF8CHAR.self).baseAddress,
                        CK_ULONG(nameBytes.count),
                        atrBytes.bindMemory(to: CK_BYTE.self).baseAddress,
                        CK_ULONG(atrBytes.count),
                        CK_ULONG(slot.maxInputLength),
                        CK_ULONG(slot.maxOutputLength),
                        Unmanaged.passUnretained(reader).toOpaque(),
                        hostCcidTransmitCallback
                    )
                }
            }
            if result != CKR_OK {
                return result
            }
        }
        return CK_RV(CKR_OK)
    }
}

let hostCcidTransmitCallback: PKCS11RS_HOST_CCID_TRANSMIT = {
    context,
    command,
    commandLength,
    response,
    responseLength,
    timeoutMilliseconds in
    guard let context, let responseLength else {
        return CK_RV(CKR_ARGUMENTS_BAD)
    }
    let commandLength = Int(commandLength)
    guard commandLength == 0 || command != nil else {
        return CK_RV(CKR_ARGUMENTS_BAD)
    }
    let encoded = commandLength == 0
        ? Data()
        : Data(bytes: command!, count: commandLength)
    let transport = Unmanaged<SmartCardReaderRegistration>
        .fromOpaque(context)
        .takeUnretainedValue()
    let (result, received) = transport.transmit(
        encoded,
        timeoutMilliseconds: UInt64(timeoutMilliseconds)
    )
    guard result == CKR_OK else {
        responseLength.pointee = 0
        return result
    }
    guard received.count <= Int(responseLength.pointee) else {
        responseLength.pointee = CK_ULONG(received.count)
        return CK_RV(CKR_BUFFER_TOO_SMALL)
    }
    guard received.isEmpty || response != nil else {
        responseLength.pointee = 0
        return CK_RV(CKR_ARGUMENTS_BAD)
    }
    if let response {
        received.copyBytes(to: response, count: received.count)
    }
    responseLength.pointee = CK_ULONG(received.count)
    return CK_RV(CKR_OK)
}

let enumerateCcidReadersCallback: PKCS11RS_ENUMERATE_CCID_READERS = {
    hardwareContext,
    sinkContext,
    addReader in
    guard let hardwareContext, let sinkContext, let addReader else {
        return CK_RV(CKR_ARGUMENTS_BAD)
    }
    let discovery = Unmanaged<SmartCardReaderDiscovery>
        .fromOpaque(hardwareContext)
        .takeUnretainedValue()
    return discovery.enumerate(sinkContext: sinkContext, addReader: addReader)
}
