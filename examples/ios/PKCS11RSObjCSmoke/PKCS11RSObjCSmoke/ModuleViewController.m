@import PKCS11RS;

#import "ModuleViewController.h"

static NSString *const PKCS11RSConnectorURLKey = @"PKCS11RSConnectorURL";
static NSString *const PKCS11RSFallbackConnectorURL = @"http://192.168.1.169:12345";
static NSString *const PKCS11RSSoftwareTokenName = @"iPhone smoke";
static NSString *const PKCS11RSSoftwareTokenModel = @"Software token";
static NSString *const PKCS11RSSoftwareTokenPIN = @"password";
static NSString *const PKCS11RSSoftwareX25519Label = @"iPhone smoke X25519";
static NSString *const PKCS11RSSoftwareX25519ID = @"iphone-smoke-x25519";
static NSString *const PKCS11RSHsmAuthPassword = @"password";
enum {
    PKCS11RSInitialSlotCapacity = 10,
    PKCS11RSObjectBatchCapacity = 64,
    PKCS11RSAttributeCapacity = 1024,
};
static const CK_ATTRIBUTE_TYPE PKCS11RSHsmAuthAlgorithm =
    CKA_VENDOR_DEFINED | 0x5901UL;
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

static NSString *PKCS11RSReturnValue(CK_RV value) {
    const char *name = PKCS11RS_GetReturnValueName(value);
    if (name != NULL) {
        return [NSString stringWithFormat:@"%s (0x%lx)", name, (unsigned long)value];
    }
    return [NSString stringWithFormat:@"0x%lx", (unsigned long)value];
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

@interface PKCS11RSPublicKeyIdentity : NSObject
@property(nonatomic, copy) NSData *identifier;
@property(nonatomic, copy) NSData *ecPoint;
@end

@implementation PKCS11RSPublicKeyIdentity
@end

@interface PKCS11RSHsmAuthCredential : NSObject
@property(nonatomic, copy) NSString *label;
@property(nonatomic, copy) NSString *source;
@property(nonatomic) CK_ULONG algorithm;
@property(nonatomic) CK_ULONG retries;
@property(nonatomic) BOOL touchRequired;
@property(nonatomic, copy, nullable) NSData *publicKey;
- (NSString *)algorithmName;
- (nullable NSString *)usernameWithAuthenticationKeyID:(NSData *)identifier;
@end

@implementation PKCS11RSHsmAuthCredential

- (NSString *)algorithmName {
    switch (self.algorithm) {
        case 38:
            return @"symmetric AES-128";
        case 39:
            return @"asymmetric P-256";
        default:
            return [NSString stringWithFormat:@"algorithm %lu", (unsigned long)self.algorithm];
    }
}

- (NSString *)usernameWithAuthenticationKeyID:(NSData *)identifier {
    if (identifier.length != 2) {
        return nil;
    }
    const unsigned char *bytes = identifier.bytes;
    return [NSString stringWithFormat:@":%02X%02X%@@%@",
                                      bytes[0], bytes[1], self.label, self.source];
}

- (NSString *)description {
    return [NSString stringWithFormat:@"\"%@\" @ %@, %@, retries %lu, touch %@",
                                      self.label,
                                      self.source,
                                      self.algorithmName,
                                      (unsigned long)self.retries,
                                      self.touchRequired ? @"required" : @"not required"];
}

@end


@interface PKCS11RSObjectInspection : NSObject
@property(nonatomic, copy) NSString *line;
@property(nonatomic, strong, nullable) PKCS11RSHsmAuthCredential *credential;
@property(nonatomic, strong, nullable) PKCS11RSPublicKeyIdentity *publicKey;
@end


@implementation PKCS11RSObjectInspection
@end


@interface PKCS11RSObjectInventory : NSObject
@property(nonatomic, copy) NSArray<NSString *> *lines;
@property(nonatomic, copy) NSArray<PKCS11RSHsmAuthCredential *> *credentials;
@property(nonatomic, copy) NSArray<PKCS11RSPublicKeyIdentity *> *publicKeys;
@end


@implementation PKCS11RSObjectInventory
@end


@interface PKCS11RSSlotInventory : NSObject
@property(nonatomic) CK_SLOT_ID slot;
@property(nonatomic, copy) NSString *slotDescription;
@property(nonatomic, copy) NSString *tokenLabel;
@property(nonatomic, copy) NSString *serial;
@property(nonatomic) BOOL yubiHsm;
@property(nonatomic, strong) PKCS11RSObjectInventory *objects;
@end


@implementation PKCS11RSSlotInventory
@end

@implementation ModuleViewController {
    dispatch_queue_t _moduleQueue;
    BOOL _moduleInitialized;
    NSString *_connectorURL;
    NSString *_tokenStoragePath;
    UIButton *_refreshButton;
    UILabel *_statusLabel;
    UITextView *_outputView;
    NSDate *_operationStartedAt;
    NSTimer *_operationTimer;
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
    explanation.text = @"The app calls the standard C ABI directly from Objective-C. "
                        "Refresh discovers NFC and YubiHSM tokens, matches YubiHSM Auth "
                        "credentials, and runs synchronous PKCS #11 work on a serial "
                        "background queue.";

    _refreshButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _refreshButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_refreshButton setTitle:@"Refresh" forState:UIControlStateNormal];
    [_refreshButton addTarget:self
                       action:@selector(refresh:)
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

    UIStackView *header = [[UIStackView alloc] initWithArrangedSubviews:@[
        heading,
        explanation,
        _refreshButton,
        _statusLabel,
    ]];
    header.translatesAutoresizingMaskIntoConstraints = NO;
    header.axis = UILayoutConstraintAxisVertical;
    header.alignment = UIStackViewAlignmentLeading;
    header.spacing = 12;

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

    __weak typeof(self) weakSelf = self;
    dispatch_async(_moduleQueue, ^{
        @autoreleasepool {
            NSString *report = [weakSelf inspectModuleIncludingSlots:includeSlots];
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
            });
        }
    });
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
    [defaults setObject:url forKey:PKCS11RSConnectorURLKey];

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
        @"software" : @{
            @"slots" : @[
                @{
                    @"name" : PKCS11RSSoftwareTokenName,
                    @"discovery_pin" : PKCS11RSSoftwareTokenPIN,
                },
            ],
        },
        @"yubihsm" : @{
            @"urls" : @[ url ],
            @"public_discovery" : @"0001password",
        },
        @"nfc" : @{
            @"discovery" : @YES,
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

- (PKCS11RSObjectInspection *)inspectObject:(CK_OBJECT_HANDLE)object
                                  inSession:(CK_SESSION_HANDLE)session
                                     source:(nullable NSString *)source {
    CK_OBJECT_CLASS objectClass = 0;
    CK_KEY_TYPE keyType = 0;
    CK_ULONG algorithm = 0;
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
        {PKCS11RSHsmAuthAlgorithm, &algorithm, sizeof(algorithm)},
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

    PKCS11RSObjectInspection *inspection = [[PKCS11RSObjectInspection alloc] init];
    BOOL hasCredentialMetadata =
        attributes[4].ulValueLen == sizeof(algorithm) &&
        attributes[5].ulValueLen == sizeof(retries) &&
        attributes[6].ulValueLen == sizeof(touchRequired);
    if (hasCredentialMetadata && label.length > 0 && source.length > 0) {
        PKCS11RSHsmAuthCredential *credential = [[PKCS11RSHsmAuthCredential alloc] init];
        credential.label = label;
        credential.source = source;
        credential.algorithm = algorithm;
        credential.retries = retries;
        credential.touchRequired = touchRequired != CK_FALSE;
        inspection.credential = credential;
        [parts addObject:[NSString stringWithFormat:@"YubiHSM Auth %@", credential.algorithmName]];
        [parts addObject:[NSString stringWithFormat:@"retries=%lu", (unsigned long)retries]];
        [parts addObject:[NSString stringWithFormat:@"touch=%@",
                                                    credential.touchRequired ? @"true" : @"false"]];
    }

    NSData *ecPoint = PKCS11RSAttributeData(attributes[7], ecPointStorage);
    if (attributes[0].ulValueLen == sizeof(objectClass) &&
        attributes[3].ulValueLen == sizeof(keyType) &&
        objectClass == CKO_PUBLIC_KEY && keyType == CKK_EC &&
        identifier.length > 0 && ecPoint.length > 0) {
        PKCS11RSPublicKeyIdentity *publicKey = [[PKCS11RSPublicKeyIdentity alloc] init];
        publicKey.identifier = identifier;
        publicKey.ecPoint = ecPoint;
        inspection.publicKey = publicKey;
    }
    inspection.line = [parts componentsJoinedByString:@", "];
    return inspection;
}

- (PKCS11RSObjectInventory *)objectInventoryForSession:(CK_SESSION_HANDLE)session
                                                  title:(NSString *)title
                                                 source:(nullable NSString *)source {
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
    NSMutableArray<PKCS11RSHsmAuthCredential *> *credentials = [[NSMutableArray alloc] init];
    NSMutableArray<PKCS11RSPublicKeyIdentity *> *publicKeys = [[NSMutableArray alloc] init];
    for (NSNumber *object in objects) {
        PKCS11RSObjectInspection *inspection =
            [self inspectObject:(CK_OBJECT_HANDLE)object.unsignedLongValue
                      inSession:session
                         source:source];
        [lines addObject:inspection.line];
        if (inspection.credential != nil) {
            [credentials addObject:inspection.credential];
        }
        if (inspection.publicKey != nil) {
            [publicKeys addObject:inspection.publicKey];
        }
    }
    if (failure != nil) {
        [lines addObject:[NSString stringWithFormat:@"  %@", failure]];
    }

    for (PKCS11RSHsmAuthCredential *credential in credentials) {
        NSData *labelIdentifier = [credential.label dataUsingEncoding:NSUTF8StringEncoding];
        for (PKCS11RSPublicKeyIdentity *publicKey in publicKeys) {
            if ([publicKey.identifier isEqualToData:labelIdentifier]) {
                credential.publicKey = publicKey.ecPoint;
                break;
            }
        }
    }

    PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
    inventory.lines = lines;
    inventory.credentials = credentials;
    inventory.publicKeys = publicKeys;
    return inventory;
}

- (CK_RV)loginSession:(CK_SESSION_HANDLE)session
              userType:(CK_USER_TYPE)userType
                   pin:(NSString *)pin {
    NSMutableData *pinData = [[pin dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_RV result = C_Login(session,
                           userType,
                           pinData.mutableBytes,
                           (CK_ULONG)pinData.length);
    [pinData resetBytesInRange:NSMakeRange(0, pinData.length)];
    return result;
}

- (CK_RV)initializeSoftwareToken:(CK_SLOT_ID)slot {
    NSMutableData *pin = [[PKCS11RSSoftwareTokenPIN dataUsingEncoding:NSUTF8StringEncoding]
        mutableCopy];
    NSMutableData *label = [NSMutableData dataWithLength:32];
    memset(label.mutableBytes, ' ', label.length);
    NSData *name = [PKCS11RSSoftwareTokenName dataUsingEncoding:NSUTF8StringEncoding];
    [label replaceBytesInRange:NSMakeRange(0, MIN(name.length, label.length))
                    withBytes:name.bytes];
    CK_RV result = C_InitToken(slot,
                               pin.mutableBytes,
                               (CK_ULONG)pin.length,
                               label.mutableBytes);
    [pin resetBytesInRange:NSMakeRange(0, pin.length)];
    return result;
}

- (CK_RV)initializeSoftwareUserPIN:(CK_SESSION_HANDLE)session {
    NSMutableData *pin = [[PKCS11RSSoftwareTokenPIN dataUsingEncoding:NSUTF8StringEncoding]
        mutableCopy];
    CK_RV result = C_InitPIN(session, pin.mutableBytes, (CK_ULONG)pin.length);
    [pin resetBytesInRange:NSMakeRange(0, pin.length)];
    return result;
}

- (CK_RV)findSoftwareX25519PrivateKeyInSession:(CK_SESSION_HANDLE)session
                                        object:(CK_OBJECT_HANDLE *)object
                                         found:(BOOL *)found {
    CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC_MONTGOMERY;
    NSMutableData *identifier =
        [[PKCS11RSSoftwareX25519ID dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ID, identifier.mutableBytes, identifier.length},
    };
    CK_RV result = C_FindObjectsInit(session,
                                     attributes,
                                     sizeof(attributes) / sizeof(attributes[0]));
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

- (CK_RV)generateSoftwareX25519KeyPairInSession:(CK_SESSION_HANDLE)session
                                       publicKey:(CK_OBJECT_HANDLE *)publicKey
                                      privateKey:(CK_OBJECT_HANDLE *)privateKey {
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL derive = CK_TRUE;
    const unsigned char parameterBytes[] = {
        0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65,
        0x32, 0x35, 0x35, 0x31, 0x39,
    };
    NSMutableData *parameters = [NSMutableData dataWithBytes:parameterBytes
                                                      length:sizeof(parameterBytes)];
    NSMutableData *identifier =
        [[PKCS11RSSoftwareX25519ID dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *label =
        [[PKCS11RSSoftwareX25519Label dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE publicAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, label.length},
        {CKA_ID, identifier.mutableBytes, identifier.length},
        {CKA_EC_PARAMS, parameters.mutableBytes, parameters.length},
    };
    CK_ATTRIBUTE privateAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, label.length},
        {CKA_ID, identifier.mutableBytes, identifier.length},
        {CKA_DERIVE, &derive, sizeof(derive)},
    };
    CK_MECHANISM mechanism = {CKM_EC_MONTGOMERY_KEY_PAIR_GEN, NULL_PTR, 0};
    *publicKey = CK_INVALID_HANDLE;
    *privateKey = CK_INVALID_HANDLE;
    return C_GenerateKeyPair(session,
                             &mechanism,
                             publicAttributes,
                             sizeof(publicAttributes) / sizeof(publicAttributes[0]),
                             privateAttributes,
                             sizeof(privateAttributes) / sizeof(privateAttributes[0]),
                             publicKey,
                             privateKey);
}

- (PKCS11RSObjectInventory *)softwareObjectInventoryForSlot:(CK_SLOT_ID)slot
                                                   tokenInfo:(CK_TOKEN_INFO)tokenInfo {
    NSMutableArray<NSString *> *prefix = [[NSMutableArray alloc] initWithObjects:
        @"", [NSString stringWithFormat:@"Persistent software token \"%@\":",
                                        PKCS11RSSoftwareTokenName], nil];
    BOOL tokenInitialized = (tokenInfo.flags & CKF_TOKEN_INITIALIZED) != 0;
    BOOL userPINInitialized = (tokenInfo.flags & CKF_USER_PIN_INITIALIZED) != 0;
    if (!tokenInitialized) {
        CK_RV initialize = [self initializeSoftwareToken:slot];
        if (initialize != CKR_OK) {
            [prefix addObject:[NSString stringWithFormat:@"  C_InitToken failed: %@",
                                                         PKCS11RSReturnValue(initialize)]];
            PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
            inventory.lines = prefix;
            inventory.credentials = @[];
            inventory.publicKeys = @[];
            return inventory;
        }
        [prefix addObject:@"  initialized persistent token"];
    }

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot,
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL_PTR,
                                 NULL_PTR,
                                 &session);
    if (result != CKR_OK) {
        [prefix addObject:[NSString stringWithFormat:@"  C_OpenSession failed: %@",
                                                     PKCS11RSReturnValue(result)]];
        PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
        inventory.lines = prefix;
        inventory.credentials = @[];
        inventory.publicKeys = @[];
        return inventory;
    }

    NSString *failure = nil;
    if (!tokenInitialized || !userPINInitialized) {
        CK_RV soLogin = [self loginSession:session
                                  userType:CKU_SO
                                       pin:PKCS11RSSoftwareTokenPIN];
        if (soLogin != CKR_OK) {
            failure = [NSString stringWithFormat:@"C_Login(CKU_SO) failed: %@",
                                                      PKCS11RSReturnValue(soLogin)];
        } else {
            CK_RV initializePIN = [self initializeSoftwareUserPIN:session];
            if (initializePIN == CKR_OK) {
                [prefix addObject:@"  initialized user PIN"];
            } else {
                failure = [NSString stringWithFormat:@"C_InitPIN failed: %@",
                                                          PKCS11RSReturnValue(initializePIN)];
            }
            CK_RV logout = C_Logout(session);
            if (logout != CKR_OK && failure == nil) {
                failure = [NSString stringWithFormat:@"C_Logout(CKU_SO) failed: %@",
                                                          PKCS11RSReturnValue(logout)];
            }
        }
    }

    BOOL userLoggedIn = NO;
    if (failure == nil) {
        CK_RV userLogin = [self loginSession:session
                                    userType:CKU_USER
                                         pin:PKCS11RSSoftwareTokenPIN];
        if (userLogin == CKR_OK) {
            userLoggedIn = YES;
        } else {
            failure = [NSString stringWithFormat:@"C_Login(CKU_USER) failed: %@",
                                                      PKCS11RSReturnValue(userLogin)];
        }
    }

    if (failure == nil) {
        CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
        BOOL found = NO;
        CK_RV find = [self findSoftwareX25519PrivateKeyInSession:session
                                                          object:&privateKey
                                                           found:&found];
        if (find != CKR_OK) {
            failure = [NSString stringWithFormat:@"X25519 key search failed: %@",
                                                      PKCS11RSReturnValue(find)];
        } else if (found) {
            [prefix addObject:@"  X25519 keypair already present"];
        } else {
            CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
            CK_RV generate = [self generateSoftwareX25519KeyPairInSession:session
                                                                 publicKey:&publicKey
                                                                privateKey:&privateKey];
            if (generate == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  generated X25519 keypair: public %lu, private %lu",
                    (unsigned long)publicKey,
                    (unsigned long)privateKey]];
            } else {
                failure = [NSString stringWithFormat:@"C_GenerateKeyPair(X25519) failed: %@",
                                                      PKCS11RSReturnValue(generate)];
            }
        }
    }

    PKCS11RSObjectInventory *inventory = nil;
    if (failure == nil) {
        inventory = [self objectInventoryForSession:session
                                              title:@"Objects (authenticated software session)"
                                             source:nil];
    } else {
        inventory = [[PKCS11RSObjectInventory alloc] init];
        inventory.lines = @[
            @"",
            [NSString stringWithFormat:@"Objects: skipped after %@", failure],
        ];
        inventory.credentials = @[];
        inventory.publicKeys = @[];
        [prefix addObject:[NSString stringWithFormat:@"  %@", failure]];
    }

    NSMutableArray<NSString *> *lines = [prefix mutableCopy];
    [lines addObjectsFromArray:inventory.lines];
    if (userLoggedIn) {
        CK_RV logout = C_Logout(session);
        if (logout != CKR_OK) {
            [lines addObject:[NSString stringWithFormat:@"  C_Logout failed: %@",
                                                        PKCS11RSReturnValue(logout)]];
        }
    }
    CK_RV close = C_CloseSession(session);
    if (close != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"  C_CloseSession failed: %@",
                                                    PKCS11RSReturnValue(close)]];
    }
    inventory.lines = lines;
    return inventory;
}

- (PKCS11RSObjectInventory *)publicObjectInventoryForSlot:(CK_SLOT_ID)slot
                                                   source:(NSString *)source {
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    if (result != CKR_OK) {
        PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
        inventory.lines = @[
            @"",
            [NSString stringWithFormat:@"Objects: C_OpenSession failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
        inventory.credentials = @[];
        inventory.publicKeys = @[];
        return inventory;
    }
    PKCS11RSObjectInventory *inventory = [self objectInventoryForSession:session
                                                                   title:@"Objects (public session)"
                                                                  source:source];
    result = C_CloseSession(session);
    if (result != CKR_OK) {
        inventory.lines = [inventory.lines arrayByAddingObject:
            [NSString stringWithFormat:@"  C_CloseSession failed: %@",
                                       PKCS11RSReturnValue(result)]];
    }
    return inventory;
}

- (NSArray<NSString *> *)authenticatedInventoryForSlot:(CK_SLOT_ID)slot
                                             credential:(PKCS11RSHsmAuthCredential *)credential
                                    authenticationKeyID:(NSData *)identifier {
    NSString *username = [credential usernameWithAuthenticationKeyID:identifier];
    if (username == nil) {
        return @[@"", @"YubiHSM Auth login skipped: invalid Authentication Key CKA_ID"];
    }

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV result = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    if (result != CKR_OK) {
        return @[
            @"",
            [NSString stringWithFormat:@"Authenticated objects: C_OpenSession failed: %@",
                                       PKCS11RSReturnValue(result)],
        ];
    }

    NSMutableArray<NSString *> *lines = [[NSMutableArray alloc] initWithObjects:@"", nil];
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
    if (result == CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"YubiHSM Auth login %@: %@",
                                                    username,
                                                    PKCS11RSReturnValue(result)]];
        PKCS11RSObjectInventory *inventory = [self objectInventoryForSession:session
                                                                       title:@"Objects (authenticated session)"
                                                                      source:nil];
        [lines addObjectsFromArray:inventory.lines];
        CK_RV logout = C_Logout(session);
        [lines addObject:[NSString stringWithFormat:@"C_Logout: %@",
                                                    PKCS11RSReturnValue(logout)]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"YubiHSM Auth login %@: %@",
                                                    username,
                                                    PKCS11RSReturnValue(result)]];
    }
    CK_RV close = C_CloseSession(session);
    if (close != CKR_OK) {
        [lines addObject:[NSString stringWithFormat:@"C_CloseSession: %@",
                                                    PKCS11RSReturnValue(close)]];
    }
    return lines;
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
        NSString *tokenModel = PKCS11RSFixedString(tokenInformation.model,
                                                   sizeof(tokenInformation.model));
        NSString *serial = PKCS11RSFixedString(tokenInformation.serialNumber,
                                               sizeof(tokenInformation.serialNumber));
        NSString *source = serial.length == 0 ? description : serial;
        PKCS11RSSlotInventory *inventory = [[PKCS11RSSlotInventory alloc] init];
        inventory.slot = slots[index];
        inventory.slotDescription = description;
        inventory.tokenLabel = tokenLabel;
        inventory.serial = serial;
        inventory.yubiHsm = [tokenLabel hasPrefix:@"YubiHSM #"];
        BOOL managesSoftwareToken =
            [tokenModel isEqualToString:PKCS11RSSoftwareTokenModel] &&
            [tokenLabel isEqualToString:PKCS11RSSoftwareTokenName];
        inventory.objects = managesSoftwareToken
            ? [self softwareObjectInventoryForSlot:slots[index] tokenInfo:tokenInformation]
            : [self publicObjectInventoryForSlot:slots[index] source:source];
        [slotInventories addObject:inventory];
    }

    NSMutableArray<PKCS11RSSlotInventory *> *orderedSlots = [[NSMutableArray alloc] init];
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        if (!inventory.yubiHsm) {
            [orderedSlots addObject:inventory];
        }
    }
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        if (inventory.yubiHsm) {
            [orderedSlots addObject:inventory];
        }
    }
    slotInventories = orderedSlots;

    NSMutableArray<PKCS11RSHsmAuthCredential *> *credentials = [[NSMutableArray alloc] init];
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        [credentials addObjectsFromArray:inventory.objects.credentials];
    }
    [report appendFormat:@"\nYubiHSM Auth credentials: %lu\n",
                         (unsigned long)credentials.count];
    if (credentials.count == 0) {
        [report appendString:
            @"  Discovery produced no credential (canceled, unavailable, or unsupported token).\n"];
    } else {
        for (PKCS11RSHsmAuthCredential *credential in credentials) {
            [report appendFormat:@"  %@\n", credential.description];
        }
    }
    PKCS11RSHsmAuthCredential *selectedCredential = credentials.firstObject;
    if (selectedCredential != nil) {
        [report appendFormat:@"Selected credential: %@\n", selectedCredential.description];
        [report appendString:@"Authentication key: match by public CKA_EC_POINT\n"];
    }

    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        [report appendFormat:@"\nSlot %lu: %@\n",
                             (unsigned long)inventory.slot,
                             inventory.slotDescription];
        [report appendFormat:@"  Token: %@\n", inventory.tokenLabel];
        [report appendFormat:@"  Serial: %@\n", inventory.serial];
        for (NSString *line in inventory.objects.lines) {
            [report appendFormat:@"%@\n", line];
        }

        if (inventory.yubiHsm && selectedCredential != nil) {
            NSMutableArray<PKCS11RSPublicKeyIdentity *> *matches = [[NSMutableArray alloc] init];
            if (selectedCredential.publicKey != nil) {
                for (PKCS11RSPublicKeyIdentity *publicKey in inventory.objects.publicKeys) {
                    if (publicKey.identifier.length == 2 &&
                        [publicKey.ecPoint isEqualToData:selectedCredential.publicKey]) {
                        [matches addObject:publicKey];
                    }
                }
            }
            [report appendFormat:@"YubiHSM Auth public-key matches: %lu\n",
                                 (unsigned long)matches.count];
            if (matches.count == 1) {
                PKCS11RSPublicKeyIdentity *match = matches.firstObject;
                [report appendFormat:@"Matched Authentication Key ID: %@\n",
                                     PKCS11RSHex(match.identifier)];
                NSArray<NSString *> *authenticated =
                    [self authenticatedInventoryForSlot:inventory.slot
                                             credential:selectedCredential
                                    authenticationKeyID:match.identifier];
                for (NSString *line in authenticated) {
                    [report appendFormat:@"%@\n", line];
                }
            } else {
                [report appendString:@"YubiHSM Auth login skipped: match is missing or ambiguous\n"];
            }
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
