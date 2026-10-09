@import PKCS11RS;

#import "ModuleViewController.h"

static NSString *const PKCS11RSConnectorURLKey = @"PKCS11RSConnectorURL";
static NSString *const PKCS11RSFallbackConnectorURL = @"http://plankan-9.duckdns.org:12345";
static NSString *const PKCS11RSPostQuantumMLDSALabel = @"iPhone smoke ML-DSA-87";
static NSString *const PKCS11RSPostQuantumMLDSAID = @"iphone-smoke-ml-dsa-87";
static NSString *const PKCS11RSPostQuantumMLKEMLabel = @"iPhone smoke ML-KEM-1024";
static NSString *const PKCS11RSPostQuantumMLKEMID = @"iphone-smoke-ml-kem-1024";
static NSString *const PKCS11RSPostQuantumHybridKEMLabel = @"iPhone smoke MLKEM768-X25519";
static NSString *const PKCS11RSPostQuantumHybridKEMID = @"iphone-smoke-mlkem768-x25519";
static NSString *const PKCS11RSPreviewSignRegistrationLabel = @"iPhone smoke previewSign registration";
static NSString *const PKCS11RSPreviewSignDerivedKeyLabel = @"iPhone smoke previewSign ARKG-P256";
static NSString *const PKCS11RSPreviewSignRegistrationID = @"iphone-smoke-preview-sign-registration";
static NSString *const PKCS11RSPreviewSignDerivedKeyID = @"iphone-smoke-preview-sign-p256";
static NSString *const PKCS11RSPreviewSignContext = @"pkcs11rs iPhone previewSign smoke";
static NSString *const PKCS11RSHsmAuthPassword = @"password";
static NSString *const PKCS11RSPlatformCredentialName = @"iphone-qpernil-objc";
static NSString *const PKCS11RSPlatformCredentialLabel = @"iPhone qpernil Objective-C";
static const CK_ULONG PKCS11RSPlatformAuthenticationKeyID = 0x1005UL;
static const CK_ULONG PKCS11RSPlatformDomains = 0xffffUL;
enum {
    PKCS11RSInitialSlotCapacity = 10,
    PKCS11RSObjectBatchCapacity = 64,
    PKCS11RSAttributeCapacity = 1024,
    PKCS11RSMLDSAMessageLength = 32,
    PKCS11RSMLKEMSecretLength = 32,
};
static const CK_MECHANISM_TYPE PKCS11RSPreviewSignKeyPairGen =
    CKM_VENDOR_DEFINED | 0x50530001UL;
static const CK_MECHANISM_TYPE PKCS11RSPreviewSignDerive =
    CKM_VENDOR_DEFINED | 0x50530002UL;
static const CK_MECHANISM_TYPE PKCS11RSPreviewSign =
    CKM_VENDOR_DEFINED | 0x50530003UL;
static const CK_MECHANISM_TYPE PKCS11RSProjectPublicKey =
    CKM_VENDOR_DEFINED | 0x50530004UL;
static const CK_KEY_TYPE PKCS11RSPreviewSignRegistrationKeyType =
    CKK_VENDOR_DEFINED | 0x50530001UL;
static const CK_ATTRIBUTE_TYPE PKCS11RSPreviewSignRegistrationAttribute =
    CKA_VENDOR_DEFINED | 0x50530001UL;
static const CK_KEY_TYPE PKCS11RSMLKEM768X25519KeyType =
    CKK_VENDOR_DEFINED | 0x50530011UL;
static const CK_MECHANISM_TYPE PKCS11RSMLKEM768X25519KeyPairGen =
    CKM_VENDOR_DEFINED | 0x50530012UL;
static const CK_MECHANISM_TYPE PKCS11RSMLKEM768X25519 =
    CKM_VENDOR_DEFINED | 0x50530013UL;
static const CK_ATTRIBUTE_TYPE PKCS11RSHsmAuthRetries =
    CKA_VENDOR_DEFINED | 0x5902UL;
static const CK_ATTRIBUTE_TYPE PKCS11RSHsmAuthTouchRequired =
    CKA_VENDOR_DEFINED | 0x5903UL;

static NSString *PKCS11RSFixedString(const CK_UTF8CHAR *bytes, NSUInteger length) {
    NSString *value = [[NSString alloc] initWithBytes:bytes
                                               length:length
                                             encoding:NSUTF8StringEncoding];
    if (value == nil) {
        return @"<invalid UTF-8>";
    }
    return [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

static BOOL PKCS11RSIsYubiHsmTokenLabel(NSString *label) {
    return [label hasPrefix:@"YubiHSM #"];
}

static BOOL PKCS11RSIsPivTokenLabel(NSString *label) {
    return [label hasPrefix:@"PIV #"];
}

static BOOL PKCS11RSIsFido2TokenLabel(NSString *label) {
    return [label hasPrefix:@"FIDO2 "];
}

static BOOL PKCS11RSIsHostTokenLabel(NSString *label) {
    return [label isEqualToString:@"Secure Enclave"];
}

static NSString *PKCS11RSReturnValue(CK_RV value) {
    const char *name = PKCS11RS_GetReturnValueName(value);
    if (name != NULL) {
        return [NSString stringWithFormat:@"%s (0x%lx)", name, (unsigned long)value];
    }
    return [NSString stringWithFormat:@"0x%lx", (unsigned long)value];
}

static NSString *PKCS11RSUserType(CK_USER_TYPE userType) {
    switch (userType) {
        case CKU_SO: return @"CKU_SO";
        case CKU_USER: return @"CKU_USER";
        case CKU_CONTEXT_SPECIFIC: return @"CKU_CONTEXT_SPECIFIC";
        default: return [NSString stringWithFormat:@"CK_USER_TYPE(%lu)",
                                                   (unsigned long)userType];
    }
}

static NSString *PKCS11RSLoginResult(CK_USER_TYPE userType, CK_RV result) {
    return [NSString stringWithFormat:@"  C_Login(%@) => %@",
                                      PKCS11RSUserType(userType),
                                      PKCS11RSReturnValue(result)];
}

static NSString *PKCS11RSLoginUserResult(NSString *username,
                                         CK_RV result,
                                         NSString *credential) {
    NSString *suffix = credential == nil
        ? @""
        : [NSString stringWithFormat:@" using %@", credential];
    return [NSString stringWithFormat:@"  C_LoginUser(CKU_USER, %@) => %@%@",
                                      username,
                                      PKCS11RSReturnValue(result),
                                      suffix];
}

static NSString *PKCS11RSAuthenticatedCredential(CK_SESSION_HANDLE session) {
    CK_ULONG length = 0;
    CK_RV result = PKCS11RS_GetAuthenticatedCredential(session, NULL_PTR, &length);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"<credential query failed: %@>",
                                          PKCS11RSReturnValue(result)];
    }
    NSMutableData *value = [[NSMutableData alloc] initWithLength:(NSUInteger)length];
    result = PKCS11RS_GetAuthenticatedCredential(session, value.mutableBytes, &length);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"<credential query failed: %@>",
                                          PKCS11RSReturnValue(result)];
    }
    NSString *description = [[NSString alloc] initWithBytes:value.bytes
                                                     length:(NSUInteger)length
                                                   encoding:NSUTF8StringEncoding];
    return description == nil ? @"<invalid UTF-8>" : description;
}

static NSArray<NSString *> *PKCS11RSAuthenticationDiagnostics(CK_SESSION_HANDLE session) {
    NSMutableArray<NSString *> *lines = [[NSMutableArray alloc] init];
    CK_ULONG length = 0;
    CK_RV result = PKCS11RS_GetSecureChannel(session, NULL_PTR, &length);
    if (result == CKR_OK) {
        NSMutableData *value = [NSMutableData dataWithLength:(NSUInteger)length];
        result = PKCS11RS_GetSecureChannel(session, value.mutableBytes, &length);
        if (result == CKR_OK) {
            NSString *channel = [[NSString alloc] initWithBytes:value.bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
            [lines addObject:[NSString stringWithFormat:@"  Secure channel: %@", channel]];
        }
    }
    if (result != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  Secure channel query failed: %@", PKCS11RSReturnValue(result)]];
    }
    [lines addObject:[NSString stringWithFormat:@"  Credential: %@", PKCS11RSAuthenticatedCredential(session)]];
    return lines;
}

static NSString *PKCS11RSHex(NSData *value) {
    const unsigned char *bytes = value.bytes;
    NSMutableArray<NSString *> *parts = [[NSMutableArray alloc] initWithCapacity:value.length];
    for (NSUInteger index = 0; index < value.length; index++) {
        [parts addObject:[NSString stringWithFormat:@"%02X", bytes[index]]];
    }
    return [parts componentsJoinedByString:@":"];
}

static NSString *PKCS11RSObjectClass(CK_OBJECT_CLASS value) {
    const char *name = PKCS11RS_GetObjectClassName(value);
    return name == NULL ? [NSString stringWithFormat:@"class 0x%lx", (unsigned long)value]
                        : [NSString stringWithUTF8String:name];
}

static NSString *PKCS11RSKeyType(CK_KEY_TYPE value) {
    const char *name = PKCS11RS_GetKeyTypeName(value);
    return name == NULL ? [NSString stringWithFormat:@"key type 0x%lx", (unsigned long)value]
                        : [NSString stringWithUTF8String:name];
}

static NSData *PKCS11RSAttributeData(CK_ATTRIBUTE attribute, NSData *storage) {
    if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        attribute.ulValueLen > storage.length) {
        return nil;
    }
    return [storage subdataWithRange:NSMakeRange(0, (NSUInteger)attribute.ulValueLen)];
}

static NSString *PKCS11RSHsmAuthAlgorithmName(CK_KEY_TYPE keyType) {
    switch (keyType) {
        case CKK_YUBICO_HSMAUTH_CREDENTIAL_SYMMETRIC:
        case CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_SYMMETRIC:
            return @"symmetric AES-128";
        case CKK_YUBICO_HSMAUTH_CREDENTIAL_ASYMMETRIC:
        case CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_ASYMMETRIC:
            return @"asymmetric P-256";
        default:
            return nil;
    }
}

@interface PKCS11RSObjectInventory : NSObject
@property(nonatomic, copy) NSArray<NSString *> *lines;
@end


@implementation PKCS11RSObjectInventory
@end


@interface PKCS11RSAuthorizedSession : NSObject
@property(nonatomic) CK_SESSION_HANDLE session;
@end


@implementation PKCS11RSAuthorizedSession
@end


@interface PKCS11RSPostQuantumSupport : NSObject
@property(nonatomic, copy) NSArray<NSString *> *lines;
@property(nonatomic) BOOL mlDsa;
@property(nonatomic) BOOL mlKem;
@property(nonatomic) BOOL hybridKem;
@property(nonatomic, readonly) BOOL any;
@end


@implementation PKCS11RSPostQuantumSupport
- (BOOL)any {
    return self.mlDsa || self.mlKem || self.hybridKem;
}
@end


@interface PKCS11RSPostQuantumPair : NSObject
@property(nonatomic) CK_RV result;
@property(nonatomic) CK_OBJECT_HANDLE publicKey;
@property(nonatomic) CK_OBJECT_HANDLE privateKey;
@property(nonatomic, copy) NSString *status;
@end


@implementation PKCS11RSPostQuantumPair
@end


@interface PKCS11RSSlotInventory : NSObject
@property(nonatomic) CK_SLOT_ID slot;
@property(nonatomic, copy) NSString *slotDescription;
@property(nonatomic, copy) NSString *tokenLabel;
@property(nonatomic, copy) NSString *serial;
@property(nonatomic) BOOL yubiHsm;
@property(nonatomic, strong) PKCS11RSAuthorizedSession *authorization;
@property(nonatomic) CK_RV authenticationResult;
@property(nonatomic, copy) NSString *authenticatedCredential;
@end


@implementation PKCS11RSSlotInventory
@end

@implementation ModuleViewController {
    dispatch_queue_t _moduleQueue;
    BOOL _moduleInitialized;
    NSString *_connectorURL;
    NSString *_tokenStoragePath;
    UIButton *_refreshButton;
    UIButton *_provisionButton;
    UILabel *_statusLabel;
    UITextView *_outputView;
    NSDate *_operationStartedAt;
    NSTimer *_operationTimer;
    BOOL _platformCredentialProvisioned;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"PKCS11RS Objective-C";
    _moduleQueue = dispatch_queue_create("com.nilssoncrypto.pkcs11rs.objc-smoke",
                                         DISPATCH_QUEUE_SERIAL);

    UILabel *heading = [[UILabel alloc] init];
    heading.translatesAutoresizingMaskIntoConstraints = NO;
    heading.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle2];
    heading.text = @"PKCS #11 module inventory";

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    explanation.numberOfLines = 0;
    explanation.text = @"This Objective-C smoke app inspects PKCS #11 slots and "
                        "provisions a platform credential.";

    _refreshButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _refreshButton.translatesAutoresizingMaskIntoConstraints = NO;
    _refreshButton.configuration = [UIButtonConfiguration borderedButtonConfiguration];
    [_refreshButton setTitle:@"Refresh" forState:UIControlStateNormal];
    [_refreshButton addTarget:self
                       action:@selector(refresh:)
             forControlEvents:UIControlEventTouchUpInside];

    _provisionButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _provisionButton.translatesAutoresizingMaskIntoConstraints = NO;
    _provisionButton.configuration =
        [UIButtonConfiguration borderedProminentButtonConfiguration];
    [_provisionButton setTitle:@"Provision platform credential"
                      forState:UIControlStateNormal];
    [_provisionButton addTarget:self
                         action:@selector(provisionPhone:)
               forControlEvents:UIControlEventTouchUpInside];

    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.font = [UIFont monospacedDigitSystemFontOfSize:12
                                                        weight:UIFontWeightMedium];
    _statusLabel.textColor = UIColor.secondaryLabelColor;
    _statusLabel.hidden = YES;

    _outputView = [[UITextView alloc] init];
    _outputView.translatesAutoresizingMaskIntoConstraints = NO;
    _outputView.backgroundColor = UIColor.secondarySystemBackgroundColor;
    _outputView.editable = NO;
    _outputView.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _outputView.text = @"Not inspected yet.";

    UIStackView *buttonRow = [[UIStackView alloc] initWithArrangedSubviews:@[
        _provisionButton,
        _refreshButton,
    ]];
    buttonRow.axis = UILayoutConstraintAxisHorizontal;
    buttonRow.alignment = UIStackViewAlignmentCenter;
    buttonRow.distribution = UIStackViewDistributionEqualSpacing;

    UIStackView *header = [[UIStackView alloc] initWithArrangedSubviews:@[
        heading,
        explanation,
        buttonRow,
        _statusLabel,
    ]];
    header.translatesAutoresizingMaskIntoConstraints = NO;
    header.axis = UILayoutConstraintAxisVertical;
    header.alignment = UIStackViewAlignmentLeading;
    header.spacing = 12;
    [buttonRow.widthAnchor constraintEqualToAnchor:header.widthAnchor].active = YES;

    [self.view addSubview:header];
    [self.view addSubview:_outputView];

    UILayoutGuide *safeArea = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [header.topAnchor constraintEqualToAnchor:safeArea.topAnchor constant:20],
        [header.leadingAnchor constraintEqualToAnchor:safeArea.leadingAnchor constant:20],
        [header.trailingAnchor constraintEqualToAnchor:safeArea.trailingAnchor constant:-20],
        [_outputView.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:16],
        [_outputView.leadingAnchor constraintEqualToAnchor:safeArea.leadingAnchor constant:20],
        [_outputView.trailingAnchor constraintEqualToAnchor:safeArea.trailingAnchor constant:-20],
        [_outputView.bottomAnchor constraintEqualToAnchor:safeArea.bottomAnchor constant:-20],
    ]];

    [self performInspectionIncludingSlots:NO];
}

- (void)refresh:(id)sender {
    (void)sender;
    [self performInspectionIncludingSlots:YES];
}

- (void)provisionPhone:(id)sender {
    (void)sender;
    BOOL unprovision = _platformCredentialProvisioned;
    [_operationTimer invalidate];
    _operationStartedAt = [NSDate date];
    [self updateOperationStatus:nil];
    _operationTimer = [NSTimer scheduledTimerWithTimeInterval:1
                                                       target:self
                                                     selector:@selector(updateOperationStatus:)
                                                     userInfo:nil
                                                      repeats:YES];
    _refreshButton.enabled = NO;
    _provisionButton.enabled = NO;

    __weak typeof(self) weakSelf = self;
    dispatch_async(_moduleQueue, ^{
        @autoreleasepool {
            ModuleViewController *backgroundSelf = weakSelf;
            if (backgroundSelf == nil) {
                return;
            }
            NSString *report = unprovision
                ? [backgroundSelf unprovisionPhoneReport]
                : [backgroundSelf provisionPhoneReport];
            BOOL provisioned = [backgroundSelf platformCredentialExists];
            dispatch_async(dispatch_get_main_queue(), ^{
                ModuleViewController *strongSelf = weakSelf;
                if (strongSelf == nil) {
                    return;
                }
                strongSelf->_outputView.text = report;
                [strongSelf->_operationTimer invalidate];
                strongSelf->_operationTimer = nil;
                strongSelf->_operationStartedAt = nil;
                strongSelf->_statusLabel.hidden = YES;
                strongSelf->_refreshButton.enabled = YES;
                strongSelf->_provisionButton.enabled = YES;
                [strongSelf setPlatformCredentialProvisioned:provisioned];
            });
        }
    });
}

- (void)performInspectionIncludingSlots:(BOOL)includeSlots {
    [_operationTimer invalidate];
    _operationStartedAt = [NSDate date];
    [self updateOperationStatus:nil];
    _operationTimer = [NSTimer scheduledTimerWithTimeInterval:1
                                                       target:self
                                                     selector:@selector(updateOperationStatus:)
                                                     userInfo:nil
                                                      repeats:YES];
    _refreshButton.enabled = NO;
    _provisionButton.enabled = NO;

    __weak typeof(self) weakSelf = self;
    dispatch_async(_moduleQueue, ^{
        @autoreleasepool {
            NSString *report = [weakSelf inspectModuleIncludingSlots:includeSlots];
            BOOL provisioned = [weakSelf platformCredentialExists];
            dispatch_async(dispatch_get_main_queue(), ^{
                ModuleViewController *strongSelf = weakSelf;
                if (strongSelf == nil) {
                    return;
                }
                strongSelf->_outputView.text = report;
                [strongSelf->_operationTimer invalidate];
                strongSelf->_operationTimer = nil;
                strongSelf->_operationStartedAt = nil;
                strongSelf->_statusLabel.hidden = YES;
                strongSelf->_refreshButton.enabled = YES;
                strongSelf->_provisionButton.enabled = YES;
                [strongSelf setPlatformCredentialProvisioned:provisioned];
            });
        }
    });
}

- (void)setPlatformCredentialProvisioned:(BOOL)provisioned {
    _platformCredentialProvisioned = provisioned;
    NSString *title = provisioned ? @"Unprovision platform credential"
                                  : @"Provision platform credential";
    [_provisionButton setTitle:title forState:UIControlStateNormal];
}

- (BOOL)platformCredentialExists {
    NSData *credentialName =
        [PKCS11RSPlatformCredentialName dataUsingEncoding:NSUTF8StringEncoding];
    CK_BYTE publicKey[65] = {0};
    CK_ULONG publicKeyLength = sizeof(publicKey);
    return PKCS11RS_PlatformCredentialGetPublicKey(credentialName.bytes,
                                                    (CK_ULONG)credentialName.length,
                                                    publicKey,
                                                    &publicKeyLength) == CKR_OK;
}

- (void)updateOperationStatus:(nullable NSTimer *)timer {
    (void)timer;
    if (_operationStartedAt == nil) {
        return;
    }
    NSInteger seconds = MAX(0, (NSInteger)-[_operationStartedAt timeIntervalSinceNow]);
    _statusLabel.text = [NSString stringWithFormat:@"Working… %lds", (long)seconds];
    _statusLabel.hidden = NO;
}

- (NSString *)configurationJSON {
    NSDictionary<NSString *, NSString *> *environment = NSProcessInfo.processInfo.environment;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSString *url = environment[@"PKCS11RS_YUBIHSM_URLS"];
    if (url == nil) {
        url = [defaults stringForKey:PKCS11RSConnectorURLKey];
    }
    if (url == nil) {
        url = PKCS11RSFallbackConnectorURL;
    }

    NSURL *applicationSupport =
        [NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory
                                             inDomains:NSUserDomainMask].firstObject;
    NSString *tokenStoragePath =
        [[applicationSupport URLByAppendingPathComponent:@"pkcs11rs-smoke" isDirectory:YES] path];

    NSDictionary *configuration = @{
        @"version" : @1,
        @"logging" : @{
            @"level" : @"debug",
        },
        @"storage" : @{
            @"tokens" : tokenStoragePath,
        },
        @"platform" : @{ @"enabled" : @YES },
        @"yubihsm" : @{
            @"urls" : @[ url ],
            @"public_discovery" : @"0001password",
        },
        @"nfc" : @{
            @"discovery" : @YES,
        },
        @"ccid" : @{
            @"secure_channel" : environment[@"PKCS11RS_CCID_SECURE_CHANNEL"] ?: @"scp11b",
        },
    };

    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:configuration
                                                   options:NSJSONWritingSortedKeys
                                                     error:&error];
    if (data == nil) {
        return nil;
    }
    _connectorURL = url;
    _tokenStoragePath = tokenStoragePath;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSString *)descriptionForObject:(CK_OBJECT_HANDLE)object
                         inSession:(CK_SESSION_HANDLE)session {
    CK_OBJECT_CLASS objectClass = 0;
    CK_KEY_TYPE keyType = 0;
    CK_ULONG retries = 0;
    CK_BBOOL touchRequired = CK_FALSE;
    NSMutableData *labelStorage = [NSMutableData dataWithLength:PKCS11RSAttributeCapacity];
    NSMutableData *identifierStorage = [NSMutableData dataWithLength:PKCS11RSAttributeCapacity];
    NSMutableData *ecPointStorage = [NSMutableData dataWithLength:PKCS11RSAttributeCapacity];
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_LABEL, labelStorage.mutableBytes, labelStorage.length},
        {CKA_ID, identifierStorage.mutableBytes, identifierStorage.length},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {PKCS11RSHsmAuthRetries, &retries, sizeof(retries)},
        {PKCS11RSHsmAuthTouchRequired, &touchRequired, sizeof(touchRequired)},
        {CKA_EC_POINT, ecPointStorage.mutableBytes, ecPointStorage.length},
    };
    CK_RV result = C_GetAttributeValue(session,
                                       object,
                                       attributes,
                                       sizeof(attributes) / sizeof(attributes[0]));

    NSMutableArray<NSString *> *parts = [[NSMutableArray alloc] init];
    [parts addObject:[NSString stringWithFormat:@"  %lu", (unsigned long)object]];
    if (attributes[0].ulValueLen == sizeof(objectClass)) {
        [parts addObject:PKCS11RSObjectClass(objectClass)];
    } else {
        [parts addObject:@"class unavailable"];
    }

    NSData *labelData = PKCS11RSAttributeData(attributes[1], labelStorage);
    NSString *label = labelData.length == 0
        ? nil
        : [[NSString alloc] initWithData:labelData encoding:NSUTF8StringEncoding];
    if (label.length > 0) {
        [parts addObject:[NSString stringWithFormat:@"label=\"%@\"", label]];
    }

    NSData *identifier = PKCS11RSAttributeData(attributes[2], identifierStorage);
    if (identifier.length > 0) {
        [parts addObject:[NSString stringWithFormat:@"id=%@", PKCS11RSHex(identifier)]];
    }
    if (attributes[3].ulValueLen == sizeof(keyType)) {
        [parts addObject:[NSString stringWithFormat:@"key=%@", PKCS11RSKeyType(keyType)]];
    }
    if (result != CKR_OK && result != CKR_ATTRIBUTE_TYPE_INVALID &&
        result != CKR_ATTRIBUTE_SENSITIVE && result != CKR_BUFFER_TOO_SMALL) {
        [parts addObject:[NSString stringWithFormat:@"attributes failed: %@",
                                                    PKCS11RSReturnValue(result)]];
    }

    NSString *algorithmName = PKCS11RSHsmAuthAlgorithmName(keyType);
    BOOL hasCredentialMetadata =
        algorithmName != nil &&
        attributes[4].ulValueLen == sizeof(retries) &&
        attributes[5].ulValueLen == sizeof(touchRequired);
    if (hasCredentialMetadata) {
        [parts addObject:[NSString stringWithFormat:@"YubiHSM Auth %@", algorithmName]];
        [parts addObject:[NSString stringWithFormat:@"retries=%lu", (unsigned long)retries]];
        [parts addObject:[NSString stringWithFormat:@"touch=%@",
                                                    touchRequired != CK_FALSE ? @"true" : @"false"]];
    }

    return [parts componentsJoinedByString:@", "];
}

- (PKCS11RSObjectInventory *)objectInventoryForSession:(CK_SESSION_HANDLE)session
                                                  title:(NSString *)title {
    NSMutableArray<NSNumber *> *objects = [[NSMutableArray alloc] init];
    NSString *failure = nil;
    CK_RV result = C_FindObjectsInit(session, NULL_PTR, 0);
    if (result == CKR_OK) {
        while (YES) {
            CK_OBJECT_HANDLE batch[PKCS11RSObjectBatchCapacity];
            CK_ULONG count = 0;
            result = C_FindObjects(session, batch, PKCS11RSObjectBatchCapacity, &count);
            if (result != CKR_OK) {
                failure = [NSString stringWithFormat:@"C_FindObjects failed: %@",
                                                       PKCS11RSReturnValue(result)];
                break;
            }
            if (count > PKCS11RSObjectBatchCapacity) {
                failure = [NSString stringWithFormat:@"C_FindObjects returned invalid count %lu",
                                                       (unsigned long)count];
                break;
            }
            for (CK_ULONG index = 0; index < count; index++) {
                [objects addObject:@(batch[index])];
            }
            if (count == 0) {
                break;
            }
        }
        CK_RV finalize = C_FindObjectsFinal(session);
        if (finalize != CKR_OK && failure == nil) {
            failure = [NSString stringWithFormat:@"C_FindObjectsFinal failed: %@",
                                                   PKCS11RSReturnValue(finalize)];
        }
    } else {
        failure = [NSString stringWithFormat:@"C_FindObjectsInit failed: %@",
                                               PKCS11RSReturnValue(result)];
    }

    NSMutableArray<NSString *> *lines = [[NSMutableArray alloc] initWithObjects:
        @"", [NSString stringWithFormat:@"%@: %lu", title, (unsigned long)objects.count], nil];
    for (NSNumber *object in objects) {
        [lines addObject:[self descriptionForObject:(CK_OBJECT_HANDLE)object.unsignedLongValue
                                          inSession:session]];
    }
    if (failure != nil) {
        [lines addObject:[NSString stringWithFormat:@"  %@", failure]];
    }

    PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
    inventory.lines = lines;
    return inventory;
}

- (CK_RV)exerciseMLDSAInSession:(CK_SESSION_HANDLE)session
                               publicKey:(CK_OBJECT_HANDLE)publicKey
                              privateKey:(CK_OBJECT_HANDLE)privateKey
                         signatureLength:(CK_ULONG *)signatureLength
                        signMilliseconds:(double *)signMilliseconds
                      verifyMilliseconds:(double *)verifyMilliseconds
                         failedOperation:(NSString * __autoreleasing *)failedOperation {
    NSMutableData *message = [NSMutableData dataWithLength:PKCS11RSMLDSAMessageLength];
    CK_RV result = C_GenerateRandom(session, message.mutableBytes, message.length);
    if (result != CKR_OK) {
        *failedOperation = @"C_GenerateRandom";
        return result;
    }
    CK_MECHANISM mechanism = {CKM_ML_DSA, NULL_PTR, 0};
    NSTimeInterval signStart = NSProcessInfo.processInfo.systemUptime;
    result = C_SignInit(session, &mechanism, privateKey);
    if (result != CKR_OK) {
        *failedOperation = @"C_SignInit";
        return result;
    }
    *signatureLength = 0;
    result = C_Sign(session,
                    message.mutableBytes,
                    message.length,
                    NULL_PTR,
                    signatureLength);
    if (result != CKR_OK) {
        *failedOperation = @"C_Sign(size)";
        return result;
    }
    NSMutableData *signature = [NSMutableData dataWithLength:*signatureLength];
    result = C_Sign(session,
                    message.mutableBytes,
                    message.length,
                    signature.mutableBytes,
                    signatureLength);
    *signMilliseconds = (NSProcessInfo.processInfo.systemUptime - signStart) * 1000.0;
    if (result != CKR_OK) {
        *failedOperation = @"C_Sign";
        return result;
    }
    signature.length = *signatureLength;

    NSTimeInterval verifyStart = NSProcessInfo.processInfo.systemUptime;
    result = C_VerifyInit(session, &mechanism, publicKey);
    if (result != CKR_OK) {
        *failedOperation = @"C_VerifyInit";
        return result;
    }
    result = C_Verify(session,
                      message.mutableBytes,
                      message.length,
                      signature.mutableBytes,
                      signature.length);
    *verifyMilliseconds = (NSProcessInfo.processInfo.systemUptime - verifyStart) * 1000.0;
    *failedOperation = @"C_Verify";
    return result;
}

- (CK_RV)attributeValueInSession:(CK_SESSION_HANDLE)session
                                      key:(CK_OBJECT_HANDLE)key
                                     type:(CK_ATTRIBUTE_TYPE)type
                                    value:(NSData * __autoreleasing *)value {
    CK_ATTRIBUTE attribute = {type, NULL_PTR, 0};
    CK_RV result = C_GetAttributeValue(session, key, &attribute, 1);
    if (result != CKR_OK) {
        return result;
    }
    if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        return CKR_ATTRIBUTE_SENSITIVE;
    }
    NSMutableData *storage = [NSMutableData dataWithLength:attribute.ulValueLen];
    attribute.pValue = storage.mutableBytes;
    result = C_GetAttributeValue(session, key, &attribute, 1);
    if (result != CKR_OK) {
        return result;
    }
    storage.length = attribute.ulValueLen;
    *value = storage;
    return CKR_OK;
}

- (CK_RV)exerciseKEMInSession:(CK_SESSION_HANDLE)session
                               publicKey:(CK_OBJECT_HANDLE)publicKey
                              privateKey:(CK_OBJECT_HANDLE)privateKey
                               mechanism:(CK_MECHANISM_TYPE)mechanismType
                         constructionName:(NSString *)constructionName
                        ciphertextLength:(CK_ULONG *)ciphertextLength
                 encapsulateMilliseconds:(double *)encapsulateMilliseconds
                 decapsulateMilliseconds:(double *)decapsulateMilliseconds
                         failedOperation:(NSString * __autoreleasing *)failedOperation {
    CK_MECHANISM mechanism = {mechanismType, NULL_PTR, 0};
    CK_OBJECT_HANDLE encapsulatedSecret = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decapsulatedSecret = CK_INVALID_HANDLE;
    CK_BBOOL token = CK_FALSE;
    CK_BBOOL sensitive = CK_FALSE;
    CK_BBOOL extractable = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_ULONG valueLength = PKCS11RSMLKEMSecretLength;
    CK_ATTRIBUTE secretAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE_LEN, &valueLength, sizeof(valueLength)},
    };

    *ciphertextLength = 0;
    NSTimeInterval encapsulateStart = NSProcessInfo.processInfo.systemUptime;
    CK_RV result = C_EncapsulateKey(session,
                                    &mechanism,
                                    publicKey,
                                    NULL_PTR,
                                    0,
                                    NULL_PTR,
                                    ciphertextLength,
                                    &encapsulatedSecret);
    if (result != CKR_OK) {
        *failedOperation = @"C_EncapsulateKey(size)";
        return result;
    }
    NSMutableData *ciphertext = [NSMutableData dataWithLength:*ciphertextLength];
    result = C_EncapsulateKey(session,
                              &mechanism,
                              publicKey,
                              secretAttributes,
                              sizeof(secretAttributes) / sizeof(secretAttributes[0]),
                              ciphertext.mutableBytes,
                              ciphertextLength,
                              &encapsulatedSecret);
    *encapsulateMilliseconds =
        (NSProcessInfo.processInfo.systemUptime - encapsulateStart) * 1000.0;
    if (result != CKR_OK) {
        *failedOperation = @"C_EncapsulateKey";
        return result;
    }
    ciphertext.length = *ciphertextLength;

    NSTimeInterval decapsulateStart = NSProcessInfo.processInfo.systemUptime;
    result = C_DecapsulateKey(session,
                              &mechanism,
                              privateKey,
                              secretAttributes,
                              sizeof(secretAttributes) / sizeof(secretAttributes[0]),
                              ciphertext.mutableBytes,
                              ciphertext.length,
                              &decapsulatedSecret);
    *decapsulateMilliseconds =
        (NSProcessInfo.processInfo.systemUptime - decapsulateStart) * 1000.0;
    if (result != CKR_OK) {
        *failedOperation = @"C_DecapsulateKey";
        return result;
    }

    NSData *first = nil;
    result = [self attributeValueInSession:session
                                               key:encapsulatedSecret
                                              type:CKA_VALUE
                                             value:&first];
    if (result != CKR_OK) {
        *failedOperation = @"C_GetAttributeValue(encapsulated secret)";
        return result;
    }
    NSData *second = nil;
    result = [self attributeValueInSession:session
                                               key:decapsulatedSecret
                                              type:CKA_VALUE
                                             value:&second];
    if (result != CKR_OK) {
        *failedOperation = @"C_GetAttributeValue(decapsulated secret)";
        return result;
    }
    if (first.length != PKCS11RSMLKEMSecretLength || ![first isEqualToData:second]) {
        *failedOperation = [NSString stringWithFormat:@"%@ shared-secret comparison",
                                                      constructionName];
        return CKR_GENERAL_ERROR;
    }

    result = C_DestroyObject(session, encapsulatedSecret);
    if (result != CKR_OK) {
        *failedOperation = @"C_DestroyObject(encapsulated secret)";
        return result;
    }
    result = C_DestroyObject(session, decapsulatedSecret);
    *failedOperation = @"C_DestroyObject(decapsulated secret)";
    return result;
}

- (NSString *)sessionStateDescription:(CK_STATE)state {
    NSString *name = @"CK_STATE";
    switch (state) {
        case CKS_RO_PUBLIC_SESSION: name = @"CKS_RO_PUBLIC_SESSION"; break;
        case CKS_RO_USER_FUNCTIONS: name = @"CKS_RO_USER_FUNCTIONS"; break;
        case CKS_RW_PUBLIC_SESSION: name = @"CKS_RW_PUBLIC_SESSION"; break;
        case CKS_RW_USER_FUNCTIONS: name = @"CKS_RW_USER_FUNCTIONS"; break;
        case CKS_RW_SO_FUNCTIONS: name = @"CKS_RW_SO_FUNCTIONS"; break;
        default: break;
    }
    return [NSString stringWithFormat:@"%@ (%lu)", name, (unsigned long)state];
}

- (CK_RV)findKeyInSession:(CK_SESSION_HANDLE)session
               objectClass:(CK_OBJECT_CLASS)objectClass
                    keyType:(CK_KEY_TYPE)keyType
                 identifier:(NSData *)identifier
                     object:(CK_OBJECT_HANDLE *)object
                      found:(BOOL *)found {
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ID, (CK_VOID_PTR)identifier.bytes, (CK_ULONG)identifier.length},
    };
    CK_RV result = C_FindObjectsInit(session, attributes, 3);
    if (result != CKR_OK) {
        return result;
    }
    CK_ULONG count = 0;
    *object = CK_INVALID_HANDLE;
    result = C_FindObjects(session, object, 1, &count);
    CK_RV finalize = C_FindObjectsFinal(session);
    if (result != CKR_OK) {
        return result;
    }
    if (finalize != CKR_OK) {
        return finalize;
    }
    *found = count != 0;
    return CKR_OK;
}

- (CK_RV)deleteObjectsInSession:(CK_SESSION_HANDLE)session
                      identifier:(NSData *)identifier
                           count:(NSUInteger *)count {
    *count = 0;
    for (;;) {
        CK_ATTRIBUTE attribute = {
            CKA_ID,
            (CK_VOID_PTR)identifier.bytes,
            (CK_ULONG)identifier.length,
        };
        CK_RV result = C_FindObjectsInit(session, &attribute, 1);
        if (result != CKR_OK) {
            return result;
        }
        CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
        CK_ULONG found = 0;
        result = C_FindObjects(session, &object, 1, &found);
        CK_RV finalize = C_FindObjectsFinal(session);
        if (result != CKR_OK) {
            return result;
        }
        if (finalize != CKR_OK) {
            return finalize;
        }
        if (found == 0) {
            return CKR_OK;
        }
        result = C_DestroyObject(session, object);
        if (result != CKR_OK) {
            return result;
        }
        (*count)++;
    }
}

- (CK_RV)generatePostQuantumKeyPairInSession:(CK_SESSION_HANDLE)session
                                    mechanism:(CK_MECHANISM_TYPE)mechanismType
                                 parameterSet:(nullable NSNumber *)parameterSet
                                        label:(NSString *)labelString
                                   identifier:(NSData *)identifier
                         publicUsageAttribute:(CK_ATTRIBUTE_TYPE)publicUsageAttribute
                        privateUsageAttribute:(CK_ATTRIBUTE_TYPE)privateUsageAttribute
                                    publicKey:(CK_OBJECT_HANDLE *)publicKey
                                   privateKey:(CK_OBJECT_HANDLE *)privateKey {
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL publicUsage = CK_TRUE;
    CK_BBOOL privateUsage = CK_TRUE;
    CK_ULONG parameterSetValue = parameterSet.unsignedLongValue;
    NSMutableData *label = [[labelString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE publicAttributes[5] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, (CK_VOID_PTR)identifier.bytes, (CK_ULONG)identifier.length},
        {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)},
        {publicUsageAttribute, &publicUsage, sizeof(publicUsage)},
    };
    CK_ATTRIBUTE privateAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, (CK_VOID_PTR)identifier.bytes, (CK_ULONG)identifier.length},
        {privateUsageAttribute, &privateUsage, sizeof(privateUsage)},
    };
    CK_MECHANISM mechanism = {mechanismType, NULL_PTR, 0};
    *publicKey = CK_INVALID_HANDLE;
    *privateKey = CK_INVALID_HANDLE;
    CK_ULONG publicCount = parameterSet == nil ? 4 : 5;
    if (parameterSet == nil) {
        publicAttributes[3] = publicAttributes[4];
    }
    return C_GenerateKeyPair(session,
                             &mechanism,
                             publicAttributes,
                             publicCount,
                             privateAttributes,
                             sizeof(privateAttributes) / sizeof(privateAttributes[0]),
                             publicKey,
                             privateKey);
}

- (NSArray<NSData *> *)postQuantumIdentifiersForTokenLabel:(NSString *)tokenLabel {
    if (PKCS11RSIsPivTokenLabel(tokenLabel)) {
        const unsigned char values[] = {5, 6, 7};
        return @[
            [NSData dataWithBytes:&values[0] length:1],
            [NSData dataWithBytes:&values[1] length:1],
            [NSData dataWithBytes:&values[2] length:1],
        ];
    }
    if (PKCS11RSIsYubiHsmTokenLabel(tokenLabel)) {
        const unsigned char dsa[] = {0x7e, 0x20};
        const unsigned char kem[] = {0x7e, 0x21};
        const unsigned char hybrid[] = {0x7e, 0x22};
        return @[
            [NSData dataWithBytes:dsa length:sizeof(dsa)],
            [NSData dataWithBytes:kem length:sizeof(kem)],
            [NSData dataWithBytes:hybrid length:sizeof(hybrid)],
        ];
    }
    return @[
        [PKCS11RSPostQuantumMLDSAID dataUsingEncoding:NSUTF8StringEncoding],
        [PKCS11RSPostQuantumMLKEMID dataUsingEncoding:NSUTF8StringEncoding],
        [PKCS11RSPostQuantumHybridKEMID dataUsingEncoding:NSUTF8StringEncoding],
    ];
}

- (NSDictionary<NSString *, id> *)mechanismRequirementForSlot:(CK_SLOT_ID)slot
                                                           name:(NSString *)name
                                                      mechanism:(CK_MECHANISM_TYPE)mechanism
                                                     advertised:(BOOL)advertised
                                                  requiredFlags:(CK_FLAGS)requiredFlags {
    if (!advertised) {
        return @{ @"supported" : @NO,
                  @"line" : [NSString stringWithFormat:@"  %@: not advertised", name] };
    }
    CK_MECHANISM_INFO information = {0};
    CK_RV result = C_GetMechanismInfo(slot, mechanism, &information);
    if (result != CKR_OK) {
        return @{
            @"supported" : @NO,
            @"line" : [NSString stringWithFormat:
                @"  %@: advertised, but C_GetMechanismInfo failed: %@",
                name,
                PKCS11RSReturnValue(result)],
        };
    }
    CK_FLAGS missing = requiredFlags & ~information.flags;
    BOOL hardware = (information.flags & CKF_HW) != 0;
    NSString *suffix = missing == 0
        ? @"advertised, required flags present"
        : [NSString stringWithFormat:@"advertised, missing flags 0x%lX",
                                           (unsigned long)missing];
    return @{
        @"supported" : @(missing == 0),
        @"line" : [NSString stringWithFormat:
            @"  %@: flags=0x%lX, HW=%@, key range %lu...%lu, %@",
            name,
            (unsigned long)information.flags,
            hardware ? @"true" : @"false",
            (unsigned long)information.ulMinKeySize,
            (unsigned long)information.ulMaxKeySize,
            suffix],
    };
}

- (PKCS11RSPostQuantumSupport *)postQuantumSupportForSlot:(CK_SLOT_ID)slot {
    PKCS11RSPostQuantumSupport *support = [[PKCS11RSPostQuantumSupport alloc] init];
    CK_ULONG count = 0;
    CK_RV result = C_GetMechanismList(slot, NULL_PTR, &count);
    if (result != CKR_OK) {
        support.lines = @[
            @"",
            @"PQC mechanism report:",
            [NSString stringWithFormat:@"  C_GetMechanismList failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
        return support;
    }
    NSMutableData *storage = [NSMutableData dataWithLength:count * sizeof(CK_MECHANISM_TYPE)];
    result = C_GetMechanismList(slot, storage.mutableBytes, &count);
    while (result == CKR_BUFFER_TOO_SMALL && count * sizeof(CK_MECHANISM_TYPE) > storage.length) {
        [storage setLength:count * sizeof(CK_MECHANISM_TYPE)];
        result = C_GetMechanismList(slot, storage.mutableBytes, &count);
    }
    if (result != CKR_OK) {
        support.lines = @[
            @"",
            @"PQC mechanism report:",
            [NSString stringWithFormat:@"  C_GetMechanismList failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
        return support;
    }
    NSMutableSet<NSNumber *> *mechanisms = [[NSMutableSet alloc] init];
    CK_MECHANISM_TYPE *values = storage.mutableBytes;
    for (CK_ULONG index = 0; index < count; index++) {
        [mechanisms addObject:@(values[index])];
    }
    NSDictionary *dsaGeneration = [self mechanismRequirementForSlot:slot
        name:@"CKM_ML_DSA_KEY_PAIR_GEN"
        mechanism:CKM_ML_DSA_KEY_PAIR_GEN
        advertised:[mechanisms containsObject:@(CKM_ML_DSA_KEY_PAIR_GEN)]
        requiredFlags:CKF_GENERATE_KEY_PAIR];
    NSDictionary *dsa = [self mechanismRequirementForSlot:slot
        name:@"CKM_ML_DSA"
        mechanism:CKM_ML_DSA
        advertised:[mechanisms containsObject:@(CKM_ML_DSA)]
        requiredFlags:CKF_SIGN | CKF_VERIFY];
    NSDictionary *kemGeneration = [self mechanismRequirementForSlot:slot
        name:@"CKM_ML_KEM_KEY_PAIR_GEN"
        mechanism:CKM_ML_KEM_KEY_PAIR_GEN
        advertised:[mechanisms containsObject:@(CKM_ML_KEM_KEY_PAIR_GEN)]
        requiredFlags:CKF_GENERATE_KEY_PAIR];
    NSDictionary *kem = [self mechanismRequirementForSlot:slot
        name:@"CKM_ML_KEM"
        mechanism:CKM_ML_KEM
        advertised:[mechanisms containsObject:@(CKM_ML_KEM)]
        requiredFlags:CKF_ENCAPSULATE | CKF_DECAPSULATE];
    NSDictionary *hybridGeneration = [self mechanismRequirementForSlot:slot
        name:@"CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN"
        mechanism:PKCS11RSMLKEM768X25519KeyPairGen
        advertised:[mechanisms containsObject:@(PKCS11RSMLKEM768X25519KeyPairGen)]
        requiredFlags:CKF_GENERATE_KEY_PAIR];
    NSDictionary *hybrid = [self mechanismRequirementForSlot:slot
        name:@"CKM_PKCS11RS_MLKEM768_X25519"
        mechanism:PKCS11RSMLKEM768X25519
        advertised:[mechanisms containsObject:@(PKCS11RSMLKEM768X25519)]
        requiredFlags:CKF_ENCAPSULATE | CKF_DECAPSULATE];
    support.mlDsa = [dsaGeneration[@"supported"] boolValue] && [dsa[@"supported"] boolValue];
    support.mlKem = [kemGeneration[@"supported"] boolValue] && [kem[@"supported"] boolValue];
    support.hybridKem = [hybridGeneration[@"supported"] boolValue] &&
                        [hybrid[@"supported"] boolValue];
    support.lines = @[
        @"",
        @"PQC mechanism report:",
        dsaGeneration[@"line"],
        dsa[@"line"],
        kemGeneration[@"line"],
        kem[@"line"],
        hybridGeneration[@"line"],
        hybrid[@"line"],
    ];
    return support;
}

- (PKCS11RSPostQuantumPair *)resolvePostQuantumPairInSession:(CK_SESSION_HANDLE)session
                                                     keyType:(CK_KEY_TYPE)keyType
                                                  identifier:(NSData *)identifier
                                                   mechanism:(CK_MECHANISM_TYPE)mechanism
                                                parameterSet:(nullable NSNumber *)parameterSet
                                                       label:(NSString *)label
                                        publicUsageAttribute:(CK_ATTRIBUTE_TYPE)publicUsageAttribute
                                       privateUsageAttribute:(CK_ATTRIBUTE_TYPE)privateUsageAttribute
                                             allowGeneration:(BOOL)allowGeneration {
    PKCS11RSPostQuantumPair *pair = [[PKCS11RSPostQuantumPair alloc] init];
    pair.publicKey = CK_INVALID_HANDLE;
    pair.privateKey = CK_INVALID_HANDLE;
    BOOL foundPublic = NO;
    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    pair.result = [self findKeyInSession:session objectClass:CKO_PUBLIC_KEY keyType:keyType
                              identifier:identifier object:&publicKey found:&foundPublic];
    pair.publicKey = publicKey;
    if (pair.result != CKR_OK) {
        pair.status = @"public-key search failed";
        return pair;
    }
    BOOL foundPrivate = NO;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    pair.result = [self findKeyInSession:session objectClass:CKO_PRIVATE_KEY keyType:keyType
                              identifier:identifier object:&privateKey found:&foundPrivate];
    pair.privateKey = privateKey;
    if (pair.result != CKR_OK) {
        pair.status = @"private-key search failed";
        return pair;
    }
    if (foundPublic && foundPrivate) {
        pair.status = @"keypair already present";
        return pair;
    }
    if (!allowGeneration) {
        pair.result = CKR_OBJECT_HANDLE_INVALID;
        pair.status = @"keypair missing after SO provisioning; USER phase will not generate";
        return pair;
    }
    NSUInteger cleared = 0;
    pair.result = [self deleteObjectsInSession:session identifier:identifier count:&cleared];
    if (pair.result != CKR_OK) {
        pair.status = @"failed to clear reserved identifier";
        return pair;
    }
    CK_SESSION_INFO information = {0};
    pair.result = C_GetSessionInfo(session, &information);
    if (pair.result != CKR_OK) {
        pair.status = @"C_GetSessionInfo before C_GenerateKeyPair failed";
        return pair;
    }
    NSTimeInterval started = NSProcessInfo.processInfo.systemUptime;
    publicKey = CK_INVALID_HANDLE;
    privateKey = CK_INVALID_HANDLE;
    pair.result = [self generatePostQuantumKeyPairInSession:session
        mechanism:mechanism parameterSet:parameterSet label:label identifier:identifier
        publicUsageAttribute:publicUsageAttribute privateUsageAttribute:privateUsageAttribute
        publicKey:&publicKey privateKey:&privateKey];
    pair.publicKey = publicKey;
    pair.privateKey = privateKey;
    double milliseconds = (NSProcessInfo.processInfo.systemUptime - started) * 1000.0;
    if (pair.result == CKR_OK) {
        pair.status = cleared == 0
            ? [NSString stringWithFormat:@"generated in %.3f ms", milliseconds]
            : [NSString stringWithFormat:@"replaced %lu object(s), generated in %.3f ms",
                                               (unsigned long)cleared, milliseconds];
    } else {
        pair.status = [NSString stringWithFormat:@"C_GenerateKeyPair failed in %@",
                            [self sessionStateDescription:information.state]];
    }
    return pair;
}

- (NSArray<NSString *> *)exercisePostQuantumMechanismsInSession:(CK_SESSION_HANDLE)session
                                                      tokenLabel:(NSString *)tokenLabel
                                                         support:(PKCS11RSPostQuantumSupport *)support
                                               performOperations:(BOOL)performOperations
                                                 allowGeneration:(BOOL)allowGeneration
                                                reportPairStatus:(BOOL)reportPairStatus {
    NSMutableArray<NSString *> *lines =
        [[NSMutableArray alloc] initWithObjects:@"", @"PQC functional smoke test:", nil];
    NSArray<NSData *> *identifiers = [self postQuantumIdentifiersForTokenLabel:tokenLabel];
    if (support.mlDsa) {
        PKCS11RSPostQuantumPair *pair = [self resolvePostQuantumPairInSession:session
            keyType:CKK_ML_DSA identifier:identifiers[0] mechanism:CKM_ML_DSA_KEY_PAIR_GEN
            parameterSet:@(CKP_ML_DSA_87) label:PKCS11RSPostQuantumMLDSALabel
            publicUsageAttribute:CKA_VERIFY privateUsageAttribute:CKA_SIGN
            allowGeneration:allowGeneration];
        if (pair.result == CKR_OK) {
            if (reportPairStatus) {
                [lines addObject:[NSString stringWithFormat:@"  ML-DSA-87 %@", pair.status]];
            }
            if (performOperations) {
                CK_ULONG signatureLength = 0;
                double signMilliseconds = 0;
                double verifyMilliseconds = 0;
                NSString *operation = nil;
                CK_RV result = [self exerciseMLDSAInSession:session
                    publicKey:pair.publicKey privateKey:pair.privateKey
                    signatureLength:&signatureLength signMilliseconds:&signMilliseconds
                    verifyMilliseconds:&verifyMilliseconds failedOperation:&operation];
                [lines addObject:result == CKR_OK
                    ? [NSString stringWithFormat:
                        @"  ML-DSA-87 sign %.3f ms, verify %.3f ms (%lu-byte signature)",
                        signMilliseconds, verifyMilliseconds, (unsigned long)signatureLength]
                    : [NSString stringWithFormat:@"  advertised ML-DSA failed at %@: %@",
                        operation, PKCS11RSReturnValue(result)]];
            }
        } else {
            [lines addObject:[NSString stringWithFormat:@"  advertised ML-DSA failed: %@: %@",
                              pair.status, PKCS11RSReturnValue(pair.result)]];
        }
    } else {
        [lines addObject:@"  ML-DSA functional test skipped: required mechanism flags not advertised"];
    }
    NSArray<NSDictionary *> *kemCases = @[
        @{
            @"supported" : @(support.mlKem),
            @"name" : @"ML-KEM-1024",
            @"keyType" : @(CKK_ML_KEM),
            @"identifier" : identifiers[1],
            @"generation" : @(CKM_ML_KEM_KEY_PAIR_GEN),
            @"parameterSet" : @(CKP_ML_KEM_1024),
            @"label" : PKCS11RSPostQuantumMLKEMLabel,
            @"mechanism" : @(CKM_ML_KEM),
        },
        @{
            @"supported" : @(support.hybridKem),
            @"name" : @"MLKEM768-X25519",
            @"keyType" : @(PKCS11RSMLKEM768X25519KeyType),
            @"identifier" : identifiers[2],
            @"generation" : @(PKCS11RSMLKEM768X25519KeyPairGen),
            @"label" : PKCS11RSPostQuantumHybridKEMLabel,
            @"mechanism" : @(PKCS11RSMLKEM768X25519),
        },
    ];
    for (NSDictionary *test in kemCases) {
        NSString *name = test[@"name"];
        if (![test[@"supported"] boolValue]) {
            [lines addObject:[NSString stringWithFormat:
                @"  %@ functional test skipped: required mechanism flags not advertised", name]];
            continue;
        }
        NSNumber *parameterSet = [name isEqualToString:@"ML-KEM-1024"]
            ? test[@"parameterSet"] : nil;
        PKCS11RSPostQuantumPair *pair = [self resolvePostQuantumPairInSession:session
            keyType:[test[@"keyType"] unsignedLongValue]
            identifier:test[@"identifier"]
            mechanism:[test[@"generation"] unsignedLongValue]
            parameterSet:parameterSet
            label:test[@"label"]
            publicUsageAttribute:CKA_ENCAPSULATE
            privateUsageAttribute:CKA_DECAPSULATE
            allowGeneration:allowGeneration];
        if (pair.result != CKR_OK) {
            [lines addObject:[NSString stringWithFormat:@"  advertised %@ failed: %@: %@",
                              name, pair.status, PKCS11RSReturnValue(pair.result)]];
            continue;
        }
        if (reportPairStatus) {
            [lines addObject:[NSString stringWithFormat:@"  %@ %@", name, pair.status]];
        }
        if (!performOperations) {
            continue;
        }
        CK_ULONG ciphertextLength = 0;
        double encapsulateMilliseconds = 0;
        double decapsulateMilliseconds = 0;
        NSString *operation = nil;
        CK_RV result = [self exerciseKEMInSession:session
            publicKey:pair.publicKey privateKey:pair.privateKey
            mechanism:[test[@"mechanism"] unsignedLongValue]
            constructionName:name ciphertextLength:&ciphertextLength
            encapsulateMilliseconds:&encapsulateMilliseconds
            decapsulateMilliseconds:&decapsulateMilliseconds failedOperation:&operation];
        [lines addObject:result == CKR_OK
            ? [NSString stringWithFormat:
                @"  %@ encapsulate %.3f ms, decapsulate %.3f ms (%lu-byte ciphertext, shared secret matched)",
                name, encapsulateMilliseconds, decapsulateMilliseconds,
                (unsigned long)ciphertextLength]
            : [NSString stringWithFormat:@"  advertised %@ failed at %@: %@",
                name, operation, PKCS11RSReturnValue(result)]];
    }
    return lines;
}

- (NSArray<NSString *> *)unauthenticatedPostQuantumSmokeForSlot:(CK_SLOT_ID)slot
                                                      tokenLabel:(NSString *)tokenLabel
                                                         support:(PKCS11RSPostQuantumSupport *)support {
    if (!support.any) {
        return @[];
    }
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot,
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        return @[
            @"",
            @"PQC functional smoke test:",
            [NSString stringWithFormat:@"  C_OpenSession(RW) failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
    }
    NSMutableArray<NSString *> *lines = [[self exercisePostQuantumMechanismsInSession:session
        tokenLabel:tokenLabel support:support performOperations:YES allowGeneration:YES
        reportPairStatus:YES] mutableCopy];
    CK_RV close = C_CloseSession(session);
    if (close != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  C_CloseSession failed: %@",
                                                   PKCS11RSReturnValue(close)]];
    }
    return lines;
}

- (CK_RV)createPreviewSignRegistrationInSession:(CK_SESSION_HANDLE)session
                                     registration:(NSData **)registration {
    CK_MECHANISM mechanism = {PKCS11RSPreviewSignKeyPairGen, NULL_PTR, 0};
    CK_KEY_TYPE keyType = CKK_EC;
    CK_KEY_TYPE registrationType = PKCS11RSPreviewSignRegistrationKeyType;
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL privateValue = CK_TRUE;
    NSMutableData *label =
        [[PKCS11RSPreviewSignRegistrationLabel dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *identifier =
        [[PKCS11RSPreviewSignRegistrationID dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE publicAttributes[] = {
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, identifier.mutableBytes, (CK_ULONG)identifier.length},
    };
    CK_ATTRIBUTE privateAttributes[] = {
        {CKA_KEY_TYPE, &registrationType, sizeof(registrationType)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, identifier.mutableBytes, (CK_ULONG)identifier.length},
        {CKA_PRIVATE, &privateValue, sizeof(privateValue)},
    };
    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    CK_RV result = C_GenerateKeyPair(session,
                                     &mechanism,
                                     publicAttributes,
                                     sizeof(publicAttributes) / sizeof(publicAttributes[0]),
                                     privateAttributes,
                                     sizeof(privateAttributes) / sizeof(privateAttributes[0]),
                                     &publicKey,
                                     &privateKey);
    if (result != CKR_OK) {
        return result;
    }
    return [self attributeValueInSession:session
                                             key:privateKey
                                            type:PKCS11RSPreviewSignRegistrationAttribute
                                           value:registration];
}

- (CK_RV)importPreviewSignRegistration:(NSData *)registration
                              inSession:(CK_SESSION_HANDLE)session
                                    key:(CK_OBJECT_HANDLE *)key {
    CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = PKCS11RSPreviewSignRegistrationKeyType;
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL privateValue = CK_TRUE;
    CK_BBOOL derive = CK_TRUE;
    NSMutableData *label =
        [[PKCS11RSPreviewSignRegistrationLabel dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *identifier =
        [[PKCS11RSPreviewSignRegistrationID dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_PRIVATE, &privateValue, sizeof(privateValue)},
        {CKA_DERIVE, &derive, sizeof(derive)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, identifier.mutableBytes, (CK_ULONG)identifier.length},
        {PKCS11RSPreviewSignRegistrationAttribute,
         (CK_VOID_PTR)registration.bytes,
         (CK_ULONG)registration.length},
    };
    *key = CK_INVALID_HANDLE;
    return C_CreateObject(session,
                          attributes,
                          sizeof(attributes) / sizeof(attributes[0]),
                          key);
}

- (CK_RV)derivePreviewSignKeyInSession:(CK_SESSION_HANDLE)session
                        registrationKey:(CK_OBJECT_HANDLE)registrationKey
                                    key:(CK_OBJECT_HANDLE *)key {
    NSMutableData *context =
        [[PKCS11RSPreviewSignContext dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_MECHANISM mechanism = {
        PKCS11RSPreviewSignDerive,
        context.mutableBytes,
        (CK_ULONG)context.length,
    };
    CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL privateValue = CK_TRUE;
    CK_BBOOL sign = CK_TRUE;
    NSMutableData *label =
        [[PKCS11RSPreviewSignDerivedKeyLabel dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *identifier =
        [[PKCS11RSPreviewSignDerivedKeyID dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_PRIVATE, &privateValue, sizeof(privateValue)},
        {CKA_SIGN, &sign, sizeof(sign)},
        {CKA_LABEL, label.mutableBytes, (CK_ULONG)label.length},
        {CKA_ID, identifier.mutableBytes, (CK_ULONG)identifier.length},
    };
    *key = CK_INVALID_HANDLE;
    return C_DeriveKey(session,
                       &mechanism,
                       registrationKey,
                       attributes,
                       sizeof(attributes) / sizeof(attributes[0]),
                       key);
}

- (CK_RV)resolvePreviewSignKeyInSession:(CK_SESSION_HANDLE)session
                                     key:(CK_OBJECT_HANDLE *)key
                               operation:(NSString **)operation {
    NSData *derivedID =
        [PKCS11RSPreviewSignDerivedKeyID dataUsingEncoding:NSUTF8StringEncoding];
    BOOL found = NO;
    CK_RV result = [self findKeyInSession:session
                              objectClass:CKO_PRIVATE_KEY
                                   keyType:CKK_EC
                                identifier:derivedID
                                    object:key
                                     found:&found];
    if (result != CKR_OK) {
        *operation = @"find derived key";
        return result;
    }
    if (found) {
        *operation = @"reused persisted chain";
        return CKR_OK;
    }

    NSData *registrationID =
        [PKCS11RSPreviewSignRegistrationID dataUsingEncoding:NSUTF8StringEncoding];
    CK_OBJECT_HANDLE registrationKey = CK_INVALID_HANDLE;
    result = [self findKeyInSession:session
                        objectClass:CKO_PRIVATE_KEY
                             keyType:PKCS11RSPreviewSignRegistrationKeyType
                          identifier:registrationID
                              object:&registrationKey
                               found:&found];
    if (result != CKR_OK) {
        *operation = @"find registration";
        return result;
    }
    if (!found) {
        NSData *registration = nil;
        result = [self createPreviewSignRegistrationInSession:session
                                                  registration:&registration];
        if (result != CKR_OK) {
            *operation = @"register credential";
            return result;
        }
        result = [self importPreviewSignRegistration:registration
                                           inSession:session
                                                 key:&registrationKey];
        if (result != CKR_OK) {
            *operation = @"persist registration";
            return result;
        }
    }
    result = [self derivePreviewSignKeyInSession:session
                                  registrationKey:registrationKey
                                              key:key];
    if (result != CKR_OK) {
        *operation = @"derive P-256 key";
        return result;
    }
    *operation = @"created and persisted chain";
    return CKR_OK;
}

- (CK_RV)exercisePreviewSignInSession:(CK_SESSION_HANDLE)session
                            signingKey:(CK_OBJECT_HANDLE)signingKey
                                 lines:(NSMutableArray<NSString *> *)lines
                       signatureLength:(CK_ULONG *)signatureLength
                          milliseconds:(double *)milliseconds
                             operation:(NSString **)operation {
    CK_MECHANISM project = {PKCS11RSProjectPublicKey, NULL_PTR, 0};
    CK_BBOOL token = CK_FALSE;
    CK_BBOOL verify = CK_TRUE;
    CK_ATTRIBUTE projectionAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_VERIFY, &verify, sizeof(verify)},
    };
    CK_OBJECT_HANDLE projectedKey = CK_INVALID_HANDLE;
    CK_RV result = C_DeriveKey(session,
                               &project,
                               signingKey,
                               projectionAttributes,
                               sizeof(projectionAttributes) / sizeof(projectionAttributes[0]),
                               &projectedKey);
    if (result != CKR_OK) {
        *operation = @"project public key";
        return result;
    }
    NSMutableData *digest = [NSMutableData dataWithLength:32];
    result = C_GenerateRandom(session, digest.mutableBytes, (CK_ULONG)digest.length);
    if (result != CKR_OK) {
        C_DestroyObject(session, projectedKey);
        *operation = @"C_GenerateRandom";
        return result;
    }
    CK_MECHANISM signMechanism = {PKCS11RSPreviewSign, NULL_PTR, 0};
    NSTimeInterval started = NSProcessInfo.processInfo.systemUptime;
    result = C_SignInit(session, &signMechanism, signingKey);
    if (result != CKR_OK) {
        C_DestroyObject(session, projectedKey);
        *operation = @"C_SignInit(previewSign)";
        return result;
    }
    result = [self loginFidoInSession:session user:CKU_CONTEXT_SPECIFIC];
    [lines addObject:PKCS11RSLoginResult(CKU_CONTEXT_SPECIFIC, result)];
    [lines addObjectsFromArray:PKCS11RSAuthenticationDiagnostics(session)];
    if (result != CKR_OK) {
        C_DestroyObject(session, projectedKey);
        *operation = @"C_Login(CKU_CONTEXT_SPECIFIC)";
        return result;
    }
    *signatureLength = 0;
    result = C_Sign(session,
                    digest.mutableBytes,
                    (CK_ULONG)digest.length,
                    NULL_PTR,
                    signatureLength);
    if (result != CKR_OK) {
        C_DestroyObject(session, projectedKey);
        *operation = @"C_Sign(size)";
        return result;
    }
    NSMutableData *signature = [NSMutableData dataWithLength:*signatureLength];
    result = C_Sign(session,
                    digest.mutableBytes,
                    (CK_ULONG)digest.length,
                    signature.mutableBytes,
                    signatureLength);
    if (result != CKR_OK) {
        C_DestroyObject(session, projectedKey);
        *operation = @"C_Sign(previewSign)";
        return result;
    }
    signature.length = *signatureLength;
    CK_MECHANISM verifyMechanism = {CKM_ECDSA, NULL_PTR, 0};
    result = C_VerifyInit(session, &verifyMechanism, projectedKey);
    if (result == CKR_OK) {
        result = C_Verify(session,
                          digest.mutableBytes,
                          (CK_ULONG)digest.length,
                          signature.mutableBytes,
                          (CK_ULONG)signature.length);
        *operation = @"C_Verify(ECDSA)";
    } else {
        *operation = @"C_VerifyInit(ECDSA)";
    }
    *milliseconds = (NSProcessInfo.processInfo.systemUptime - started) * 1000.0;
    C_DestroyObject(session, projectedKey);
    return result;
}

- (BOOL)slotHasPreviewSignSupport:(CK_SLOT_ID)slot {
    CK_MECHANISM_TYPE mechanisms[] = {
        PKCS11RSPreviewSignKeyPairGen, PKCS11RSPreviewSignDerive, PKCS11RSPreviewSign,
    };
    CK_FLAGS flags[] = {CKF_GENERATE_KEY_PAIR, CKF_DERIVE, CKF_SIGN};
    for (NSUInteger index = 0; index < 3; index++) {
        CK_MECHANISM_INFO info = {0};
        if (C_GetMechanismInfo(slot, mechanisms[index], &info) != CKR_OK ||
            (info.flags & flags[index]) != flags[index]) {
            return NO;
        }
    }
    return YES;
}

// Explicit test-device credential, supplied anew and erased after each login.
// The physical smoke-test YubiKey must already have FIDO2 PIN 123456.
- (CK_RV)loginFidoInSession:(CK_SESSION_HANDLE)session user:(CK_USER_TYPE)user {
    NSMutableData *pin = [[@"123456" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_RV result = C_Login(session, user, pin.mutableBytes, (CK_ULONG)pin.length);
    [pin resetBytesInRange:NSMakeRange(0, pin.length)];
    return result;
}

- (NSArray<NSString *> *)fidoPreviewSignSmokeForSlot:(CK_SLOT_ID)slot {
    NSMutableArray<NSString *> *lines =
        [[NSMutableArray alloc] initWithObjects:@"", @"FIDO previewSign ARKG-P256:", nil];
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot,
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  open failed: %@",
                                                   PKCS11RSReturnValue(result)]];
        return lines;
    }
    result = [self loginFidoInSession:session user:CKU_USER];
    [lines addObject:PKCS11RSLoginResult(CKU_USER, result)];
    [lines addObjectsFromArray:PKCS11RSAuthenticationDiagnostics(session)];
    if (result != CKR_OK && result != CKR_USER_ALREADY_LOGGED_IN) {
        [lines addObject:@"  user login failed"];
        C_CloseSession(session);
        return lines;
    }
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    NSString *operation = nil;
    result = [self resolvePreviewSignKeyInSession:session key:&key operation:&operation];
    if (result == CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  %@", operation]];
        CK_ULONG signatureLength = 0;
        double milliseconds = 0;
        result = [self exercisePreviewSignInSession:session
                                        signingKey:key
                                             lines:lines
                                   signatureLength:&signatureLength
                                      milliseconds:&milliseconds
                                         operation:&operation];
        if (result == CKR_OK) {
            [lines addObject:[NSString stringWithFormat:
                @"  previewSign and ECDSA verification passed in %.3f ms (%lu-byte signature)",
                milliseconds,
                (unsigned long)signatureLength]];
        }
    }
    if (result != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  %@ failed: %@",
                                                   operation,
                                                   PKCS11RSReturnValue(result)]];
    }
    C_Logout(session);
    C_CloseSession(session);
    return lines;
}

- (PKCS11RSObjectInventory *)publicObjectInventoryForSlot:(CK_SLOT_ID)slot {
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    if (result != CKR_OK) {
        PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
        inventory.lines = @[
            @"",
            [NSString stringWithFormat:@"Objects: C_OpenSession failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
        return inventory;
    }
    PKCS11RSObjectInventory *inventory = [self objectInventoryForSession:session
                                                                   title:@"Objects (public session)"];
    result = C_CloseSession(session);
    if (result != CKR_OK) {
        inventory.lines = [inventory.lines arrayByAddingObject:
            [NSString stringWithFormat:@"  C_CloseSession failed: %@",
                                       PKCS11RSReturnValue(result)]];
    }
    return inventory;
}

- (PKCS11RSAuthorizedSession *)loginSourceSlot:(CK_SLOT_ID)slot result:(CK_RV *)result {
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    *result = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    if (*result != CKR_OK) {
        return nil;
    }
    *result = C_Login(session,
                      CKU_USER,
                      NULL_PTR,
                      0);
    if (*result != CKR_OK && *result != CKR_USER_ALREADY_LOGGED_IN) {
        C_CloseSession(session);
        return nil;
    }
    PKCS11RSAuthorizedSession *authorization = [[PKCS11RSAuthorizedSession alloc] init];
    authorization.session = session;
    return authorization;
}

- (BOOL)slotHasHardwareSessionKeyDerivation:(CK_SLOT_ID)slot {
    CK_MECHANISM_INFO information = {0};
    return C_GetMechanismInfo(slot, CKM_CONCATENATE_BASE_AND_KEY, &information) == CKR_OK &&
           (information.flags & CKF_HW) != 0;
}

- (void)loginYubiHsmInventory:(PKCS11RSSlotInventory *)inventory {
    NSString *username = @"pkcs11:";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(inventory.slot,
                                 CKF_SERIAL_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        inventory.authenticationResult = result;
        return;
    }

    NSMutableData *password = [[PKCS11RSHsmAuthPassword dataUsingEncoding:NSUTF8StringEncoding]
        mutableCopy];
    NSMutableData *usernameData = [[username dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    result = C_LoginUser(session,
                         CKU_USER,
                         password.mutableBytes,
                         password.length,
                         usernameData.mutableBytes,
                         usernameData.length);
    [password resetBytesInRange:NSMakeRange(0, password.length)];
    if (result == CKR_OK || result == CKR_USER_ALREADY_LOGGED_IN) {
        PKCS11RSAuthorizedSession *authorization = [[PKCS11RSAuthorizedSession alloc] init];
        authorization.session = session;
        inventory.authorization = authorization;
        inventory.authenticatedCredential = PKCS11RSAuthenticatedCredential(session);
    } else {
        C_CloseSession(session);
    }
    inventory.authenticationResult = result;
}

- (NSString *)provisionTargetSlot:(CK_SLOT_ID)slot name:(NSString *)name {
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot,
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"%@: open failed: %@",
                                          name,
                                          PKCS11RSReturnValue(result)];
    }

    NSMutableData *password =
        [[PKCS11RSHsmAuthPassword dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *bootstrapUsername =
        [[@"pkcs11:" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    result = C_LoginUser(session,
                         CKU_USER,
                         password.mutableBytes,
                         (CK_ULONG)password.length,
                         bootstrapUsername.mutableBytes,
                         (CK_ULONG)bootstrapUsername.length);
    [password resetBytesInRange:NSMakeRange(0, password.length)];
    if (result != CKR_OK) {
        C_CloseSession(session);
        return [NSString stringWithFormat:@"%@: bootstrap login failed: %@",
                                          name,
                                          PKCS11RSReturnValue(result)];
    }

    CK_BYTE capabilities[8];
    CK_BYTE delegatedCapabilities[8];
    memset(capabilities, 0xff, sizeof(capabilities));
    memset(delegatedCapabilities, 0xff, sizeof(delegatedCapabilities));
    NSData *credentialName =
        [PKCS11RSPlatformCredentialName dataUsingEncoding:NSUTF8StringEncoding];
    NSData *label = [PKCS11RSPlatformCredentialLabel dataUsingEncoding:NSUTF8StringEncoding];
    CK_ULONG provisioningResult = 0;
    result = PKCS11RS_YubiHsmProvisionPlatformCredential(
        session,
        credentialName.bytes,
        (CK_ULONG)credentialName.length,
        PKCS11RSPlatformAuthenticationKeyID,
        label.bytes,
        (CK_ULONG)label.length,
        PKCS11RSPlatformDomains,
        capabilities,
        sizeof(capabilities),
        delegatedCapabilities,
        sizeof(delegatedCapabilities),
        &provisioningResult);
    if (result != CKR_OK) {
        C_Logout(session);
        C_CloseSession(session);
        return [NSString stringWithFormat:@"%@: provisioning failed: %@",
                                          name,
                                          PKCS11RSReturnValue(result)];
    }

    NSString *action = nil;
    switch (provisioningResult) {
        case PKCS11RS_PLATFORM_PROVISIONED:
            action = @"provisioned";
            break;
        case PKCS11RS_PLATFORM_ALREADY_PROVISIONED:
            action = @"already provisioned";
            break;
        case PKCS11RS_PLATFORM_REPAIRED:
            action = @"repaired";
            break;
        default:
            action = [NSString stringWithFormat:@"provisioned (unknown result %lu)",
                                                (unsigned long)provisioningResult];
            break;
    }
    CK_RV logout = C_Logout(session);
    if (logout != CKR_OK) {
        C_CloseSession(session);
        return [NSString stringWithFormat:@"%@: %@, bootstrap logout failed: %@",
                                          name,
                                          action,
                                          PKCS11RSReturnValue(logout)];
    }

    NSString *selector = @"pkcs11:";
    NSMutableData *platformUsername =
        [[selector dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *verificationPassword =
        [[PKCS11RSHsmAuthPassword dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    result = C_LoginUser(session,
                         CKU_USER,
                         verificationPassword.mutableBytes,
                         (CK_ULONG)verificationPassword.length,
                         platformUsername.mutableBytes,
                         (CK_ULONG)platformUsername.length);
    [verificationPassword resetBytesInRange:NSMakeRange(0, verificationPassword.length)];
    if (result != CKR_OK) {
        C_CloseSession(session);
        return [NSString stringWithFormat:@"%@: %@, platform login failed: %@",
                                          name,
                                          action,
                                          PKCS11RSReturnValue(result)];
    }
    CK_BYTE random = 0;
    CK_RV verification = C_GenerateRandom(session, &random, 1);
    C_Logout(session);
    C_CloseSession(session);
    if (verification != CKR_OK) {
        return [NSString stringWithFormat:@"%@: %@, authenticated verification failed: %@",
                                          name,
                                          action,
                                          PKCS11RSReturnValue(verification)];
    }
    return [NSString stringWithFormat:@"%@: %@, login verified", name, action];
}

- (BOOL)unprovisionTargetSlot:(CK_SLOT_ID)slot
                         name:(NSString *)name
                       report:(NSString **)report {
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot,
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        *report = [NSString stringWithFormat:@"%@: open failed: %@",
                                                name,
                                                PKCS11RSReturnValue(result)];
        return NO;
    }

    NSMutableData *password =
        [[PKCS11RSHsmAuthPassword dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *bootstrapUsername =
        [[@"pkcs11:" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    result = C_LoginUser(session,
                         CKU_USER,
                         password.mutableBytes,
                         (CK_ULONG)password.length,
                         bootstrapUsername.mutableBytes,
                         (CK_ULONG)bootstrapUsername.length);
    [password resetBytesInRange:NSMakeRange(0, password.length)];
    if (result != CKR_OK) {
        C_CloseSession(session);
        *report = [NSString stringWithFormat:@"%@: bootstrap login failed: %@",
                                                name,
                                                PKCS11RSReturnValue(result)];
        return NO;
    }

    NSData *credentialName =
        [PKCS11RSPlatformCredentialName dataUsingEncoding:NSUTF8StringEncoding];
    result = PKCS11RS_YubiHsmUnprovisionPlatformCredential(
        session,
        credentialName.bytes,
        (CK_ULONG)credentialName.length,
        PKCS11RSPlatformAuthenticationKeyID);
    CK_RV logout = C_Logout(session);
    C_CloseSession(session);
    if (result != CKR_OK) {
        *report = [NSString stringWithFormat:@"%@: unprovisioning failed: %@",
                                                name,
                                                PKCS11RSReturnValue(result)];
        return NO;
    }
    if (logout != CKR_OK) {
        *report = [NSString stringWithFormat:@"%@: unprovisioned, logout failed: %@",
                                                name,
                                                PKCS11RSReturnValue(logout)];
        return NO;
    }
    *report = [NSString stringWithFormat:@"%@: unprovisioned", name];
    return YES;
}

- (NSString *)provisionPhoneReport {
    if (!_moduleInitialized) {
        NSString *initialization = [self inspectModuleIncludingSlots:NO];
        if (!_moduleInitialized) {
            return initialization;
        }
    }

    CK_ULONG count = 0;
    CK_RV result = C_GetSlotList(CK_TRUE, NULL_PTR, &count);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"C_GetSlotList(size) failed: %@",
                                          PKCS11RSReturnValue(result)];
    }
    NSMutableData *slotStorage = [NSMutableData dataWithLength:count * sizeof(CK_SLOT_ID)];
    result = C_GetSlotList(CK_TRUE, slotStorage.mutableBytes, &count);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"C_GetSlotList failed: %@",
                                          PKCS11RSReturnValue(result)];
    }

    NSMutableArray<NSNumber *> *targets = [[NSMutableArray alloc] init];
    NSMutableArray<NSString *> *names = [[NSMutableArray alloc] init];
    CK_SLOT_ID *slots = slotStorage.mutableBytes;
    for (CK_ULONG index = 0; index < count; index++) {
        CK_TOKEN_INFO token = {0};
        if (C_GetTokenInfo(slots[index], &token) != CKR_OK) {
            continue;
        }
        NSString *label = PKCS11RSFixedString(token.label, sizeof(token.label));
        if (PKCS11RSIsYubiHsmTokenLabel(label)) {
            [targets addObject:@(slots[index])];
            [names addObject:label];
        }
    }
    if (targets.count == 0) {
        return @"No YubiHSM target is present.";
    }

    NSMutableString *report = [[NSMutableString alloc] init];
    [report appendString:@"Provision this iPhone for YubiHSM login\n"];
    [report appendFormat:@"Credential: %@\n", PKCS11RSPlatformCredentialName];
    [report appendFormat:@"Authentication Key: %04lX\n\n",
                         (unsigned long)PKCS11RSPlatformAuthenticationKeyID];
    for (NSUInteger index = 0; index < targets.count; index++) {
        NSString *line = [self provisionTargetSlot:targets[index].unsignedLongValue
                                               name:names[index]];
        [report appendFormat:@"%@\n", line];
    }
    return report;
}

- (NSString *)unprovisionPhoneReport {
    if (!_moduleInitialized) {
        NSString *initialization = [self inspectModuleIncludingSlots:NO];
        if (!_moduleInitialized) {
            return initialization;
        }
    }

    CK_ULONG count = 0;
    CK_RV result = C_GetSlotList(CK_TRUE, NULL_PTR, &count);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"C_GetSlotList(size) failed: %@",
                                          PKCS11RSReturnValue(result)];
    }
    NSMutableData *slotStorage = [NSMutableData dataWithLength:count * sizeof(CK_SLOT_ID)];
    result = C_GetSlotList(CK_TRUE, slotStorage.mutableBytes, &count);
    if (result != CKR_OK) {
        return [NSString stringWithFormat:@"C_GetSlotList failed: %@",
                                          PKCS11RSReturnValue(result)];
    }

    NSMutableArray<NSNumber *> *targets = [[NSMutableArray alloc] init];
    NSMutableArray<NSString *> *names = [[NSMutableArray alloc] init];
    CK_SLOT_ID *slots = slotStorage.mutableBytes;
    for (CK_ULONG index = 0; index < count; index++) {
        CK_TOKEN_INFO token = {0};
        if (C_GetTokenInfo(slots[index], &token) != CKR_OK) {
            continue;
        }
        NSString *label = PKCS11RSFixedString(token.label, sizeof(token.label));
        if (PKCS11RSIsYubiHsmTokenLabel(label)) {
            [targets addObject:@(slots[index])];
            [names addObject:label];
        }
    }
    if (targets.count == 0) {
        return @"No YubiHSM target is present; the platform credential was retained.";
    }

    NSMutableString *report = [[NSMutableString alloc] init];
    [report appendString:@"Unprovision this iPhone from YubiHSM login\n"];
    [report appendFormat:@"Credential: %@\n", PKCS11RSPlatformCredentialName];
    [report appendFormat:@"Authentication Key: %04lX\n\n",
                         (unsigned long)PKCS11RSPlatformAuthenticationKeyID];
    BOOL allSucceeded = YES;
    for (NSUInteger index = 0; index < targets.count; index++) {
        NSString *line = nil;
        BOOL succeeded = [self unprovisionTargetSlot:targets[index].unsignedLongValue
                                                name:names[index]
                                              report:&line];
        allSucceeded = allSucceeded && succeeded;
        [report appendFormat:@"%@\n", line];
    }
    if (!allSucceeded) {
        [report appendString:@"\nThe local platform credential was retained so "
                              "unprovisioning can be retried.\n"];
        return report;
    }

    NSData *credentialName =
        [PKCS11RSPlatformCredentialName dataUsingEncoding:NSUTF8StringEncoding];
    result = PKCS11RS_PlatformCredentialDelete(credentialName.bytes,
                                                (CK_ULONG)credentialName.length);
    if (result == CKR_OK || result == CKR_OBJECT_HANDLE_INVALID) {
        [report appendString:@"\nLocal platform credential deleted.\n"];
    } else {
        [report appendFormat:@"\nLocal credential deletion failed: %@\n",
                             PKCS11RSReturnValue(result)];
    }
    return report;
}

- (NSString *)inspectModuleIncludingSlots:(BOOL)includeSlots {
    NSMutableString *report = [[NSMutableString alloc] init];

    if (!_moduleInitialized) {
        NSString *configuration = [self configurationJSON];
        if (configuration == nil) {
            [report appendString:@"Could not encode C_Initialize configuration JSON.\n"];
            return report;
        }
        CK_C_INITIALIZE_ARGS arguments = {0};
        arguments.flags = CKF_OS_LOCKING_OK;

        CK_RV result = CKR_ARGUMENTS_BAD;
        const char *configurationBytes = configuration.UTF8String;
        if (configurationBytes != NULL) {
            arguments.pReserved = (CK_VOID_PTR)configurationBytes;
            result = C_Initialize(&arguments);
        }
        [report appendFormat:@"C_Initialize: %@\n", PKCS11RSReturnValue(result)];
        if (result != CKR_OK) {
            return report;
        }
        _moduleInitialized = YES;
    } else {
        [report appendString:@"C_Initialize: already initialized\n"];
    }

    CK_INFO information = {0};
    CK_RV result = C_GetInfo(&information);
    [report appendFormat:@"C_GetInfo: %@\n", PKCS11RSReturnValue(result)];
    if (result != CKR_OK) {
        return report;
    }

    [report appendFormat:@"Cryptoki: %u.%u\n",
                         information.cryptokiVersion.major,
                         information.cryptokiVersion.minor];
    [report appendFormat:@"Library: %@ %@\n\n",
                         PKCS11RSFixedString(information.libraryDescription,
                                            sizeof(information.libraryDescription)),
                         PKCS11RSFixedString(information.manufacturerID,
                                            sizeof(information.manufacturerID))];
    [report appendString:@"Configuration: C_Initialize JSON\n"];
    [report appendFormat:@"Connector: %@\n", _connectorURL];
    [report appendFormat:@"Token storage: %@\n", _tokenStoragePath];
    [report appendString:@"Unified Logging: com.nilssoncrypto.pkcs11rs (debug)\n"];

    if (!includeSlots) {
        [report appendString:@"\nTap Refresh to discover slots and inspect tokens.\n"];
        return report;
    }

    CK_ULONG capacity = PKCS11RSInitialSlotCapacity;
    NSMutableData *slotStorage =
        [NSMutableData dataWithLength:PKCS11RSInitialSlotCapacity * sizeof(CK_SLOT_ID)];
    result = C_GetSlotList(CK_TRUE, slotStorage.mutableBytes, &capacity);
    while (result == CKR_BUFFER_TOO_SMALL &&
           (NSUInteger)capacity * sizeof(CK_SLOT_ID) > slotStorage.length) {
        [slotStorage setLength:(NSUInteger)capacity * sizeof(CK_SLOT_ID)];
        result = C_GetSlotList(CK_TRUE, slotStorage.mutableBytes, &capacity);
    }
    [report appendFormat:@"C_GetSlotList: %@\n", PKCS11RSReturnValue(result)];
    if (result != CKR_OK) {
        return report;
    }

    [report appendFormat:@"Present slots: %lu\n", (unsigned long)capacity];
    NSMutableArray<PKCS11RSSlotInventory *> *slotInventories = [[NSMutableArray alloc] init];
    CK_SLOT_ID *slots = slotStorage.mutableBytes;
    for (CK_ULONG index = 0; index < capacity; index++) {
        CK_SLOT_INFO slotInformation = {0};
        result = C_GetSlotInfo(slots[index], &slotInformation);
        if (result != CKR_OK) {
            [report appendFormat:@"\nSlot %lu: %@\n",
                                 (unsigned long)slots[index],
                                 PKCS11RSReturnValue(result)];
            continue;
        }
        CK_TOKEN_INFO tokenInformation = {0};
        result = C_GetTokenInfo(slots[index], &tokenInformation);
        if (result != CKR_OK) {
            [report appendFormat:@"  C_GetTokenInfo: %@\n", PKCS11RSReturnValue(result)];
            continue;
        }

        NSString *description = PKCS11RSFixedString(slotInformation.slotDescription,
                                                     sizeof(slotInformation.slotDescription));
        NSString *tokenLabel = PKCS11RSFixedString(tokenInformation.label,
                                                   sizeof(tokenInformation.label));
        NSString *serial = PKCS11RSFixedString(tokenInformation.serialNumber,
                                               sizeof(tokenInformation.serialNumber));
        PKCS11RSSlotInventory *inventory = [[PKCS11RSSlotInventory alloc] init];
        inventory.slot = slots[index];
        inventory.slotDescription = description;
        inventory.tokenLabel = tokenLabel;
        inventory.serial = serial;
        inventory.yubiHsm = PKCS11RSIsYubiHsmTokenLabel(tokenLabel);
        [slotInventories addObject:inventory];
    }

    NSMutableArray<PKCS11RSAuthorizedSession *> *authorizedSessions =
        [[NSMutableArray alloc] init];

    // Report slots in the same dependency order in which they are used. A
    // successful source session remains open for later YubiHSM logins.
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        if (inventory.yubiHsm) {
            continue;
        }
        [report appendFormat:@"\nSlot %lu: %@\n",
                             (unsigned long)inventory.slot,
                             inventory.slotDescription];
        [report appendFormat:@"  Token: %@\n", inventory.tokenLabel];
        [report appendFormat:@"  Serial: %@\n", inventory.serial];
        PKCS11RSPostQuantumSupport *support =
            [self postQuantumSupportForSlot:inventory.slot];
        for (NSString *line in [self publicObjectInventoryForSlot:inventory.slot].lines) {
            [report appendFormat:@"%@\n", line];
        }
        for (NSString *line in support.lines) {
            [report appendFormat:@"%@\n", line];
        }
        if (PKCS11RSIsFido2TokenLabel(inventory.tokenLabel)) {
            if ([self slotHasPreviewSignSupport:inventory.slot]) {
                for (NSString *line in [self fidoPreviewSignSmokeForSlot:inventory.slot]) {
                    [report appendFormat:@"%@\n", line];
                }
            } else {
                [report appendString:@"  previewSign skipped: required mechanisms not advertised\n"];
            }
        }
        CK_SESSION_HANDLE authenticatedSession = CK_INVALID_HANDLE;
        if (PKCS11RSIsHostTokenLabel(inventory.tokenLabel) ||
            [inventory.tokenLabel hasPrefix:@"Issuer SD #"]) {
            CK_RV sourceResult = CKR_OK;
            PKCS11RSAuthorizedSession *authorization =
                [self loginSourceSlot:inventory.slot result:&sourceResult];
            [report appendFormat:@"\n%@\n", PKCS11RSLoginResult(CKU_USER, sourceResult)];
            if (authorization != nil) {
                [authorizedSessions addObject:authorization];
                authenticatedSession = authorization.session;
                for (NSString *line in PKCS11RSAuthenticationDiagnostics(authorization.session)) {
                    [report appendFormat:@"%@\n", line];
                }
            }
        }
        if (support.any) {
            NSArray<NSString *> *pqcLines = nil;
            if (authenticatedSession != CK_INVALID_HANDLE) {
                pqcLines = [self exercisePostQuantumMechanismsInSession:authenticatedSession
                    tokenLabel:inventory.tokenLabel support:support
                    performOperations:YES allowGeneration:YES reportPairStatus:YES];
            } else {
                pqcLines = [self unauthenticatedPostQuantumSmokeForSlot:inventory.slot
                    tokenLabel:inventory.tokenLabel support:support];
            }
            for (NSString *line in pqcLines) {
                [report appendFormat:@"%@\n", line];
            }
        }
        if (authenticatedSession != CK_INVALID_HANDLE) {
            PKCS11RSObjectInventory *authenticated =
                [self objectInventoryForSession:authenticatedSession
                                          title:@"Objects (authenticated session)"];
            for (NSString *line in authenticated.lines) {
                [report appendFormat:@"%@\n", line];
            }
        }
    }

    NSMutableArray<PKCS11RSSlotInventory *> *nativeSessionKeyProviders =
        [[NSMutableArray alloc] init];
    NSMutableArray<PKCS11RSSlotInventory *> *otherYubiHsms = [[NSMutableArray alloc] init];
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        if (!inventory.yubiHsm) {
            continue;
        }
        if ([self slotHasHardwareSessionKeyDerivation:inventory.slot]) {
            [nativeSessionKeyProviders addObject:inventory];
        } else {
            [otherYubiHsms addObject:inventory];
        }
    }
    [nativeSessionKeyProviders addObjectsFromArray:otherYubiHsms];
    for (PKCS11RSSlotInventory *inventory in nativeSessionKeyProviders) {
        [report appendFormat:@"\nSlot %lu: %@\n",
                             (unsigned long)inventory.slot,
                             inventory.slotDescription];
        [report appendFormat:@"  Token: %@\n", inventory.tokenLabel];
        [report appendFormat:@"  Serial: %@\n", inventory.serial];
        for (NSString *line in [self publicObjectInventoryForSlot:inventory.slot].lines) {
            [report appendFormat:@"%@\n", line];
        }
        PKCS11RSPostQuantumSupport *support =
            [self postQuantumSupportForSlot:inventory.slot];
        for (NSString *line in support.lines) {
            [report appendFormat:@"%@\n", line];
        }
        [self loginYubiHsmInventory:inventory];
        if (inventory.authorization != nil) {
            [authorizedSessions addObject:inventory.authorization];
        }
        [report appendFormat:@"\n%@\n",
            PKCS11RSLoginUserResult(@"pkcs11:",
                                    inventory.authenticationResult,
                                    nil)];
        if (inventory.authorization != nil) {
            for (NSString *line in PKCS11RSAuthenticationDiagnostics(inventory.authorization.session)) {
                [report appendFormat:@"%@\n", line];
            }
            if (support.any) {
                for (NSString *line in [self exercisePostQuantumMechanismsInSession:
                        inventory.authorization.session
                        tokenLabel:inventory.tokenLabel
                        support:support
                        performOperations:YES
                        allowGeneration:YES
                        reportPairStatus:YES]) {
                    [report appendFormat:@"%@\n", line];
                }
            }
            for (NSString *line in [self objectInventoryForSession:inventory.authorization.session
                    title:@"Objects (authenticated session)"].lines) {
                [report appendFormat:@"%@\n", line];
            }
        } else if (support.any) {
            [report appendString:@"  PQC functional test skipped because authentication failed\n"];
        }
    }

    NSMutableArray<NSString *> *cleanupFailures = [[NSMutableArray alloc] init];
    for (PKCS11RSAuthorizedSession *authorization in authorizedSessions.reverseObjectEnumerator) {
        CK_RV close = C_CloseSession(authorization.session);
        if (close != CKR_OK) {
            [cleanupFailures addObject:
                [NSString stringWithFormat:@"C_CloseSession failed: %@",
                                           PKCS11RSReturnValue(close)]];
        }
    }
    if (cleanupFailures.count != 0) {
        [report appendString:@"\nCredential session cleanup:\n"];
        for (NSString *failure in cleanupFailures) {
            [report appendFormat:@"  %@\n", failure];
        }
    }

    return report;
}

- (void)finalizeModule {
    if (_moduleQueue == nil) {
        return;
    }
    dispatch_sync(_moduleQueue, ^{
        if (self->_moduleInitialized) {
            C_Finalize(NULL_PTR);
            self->_moduleInitialized = NO;
        }
    });
}

@end
