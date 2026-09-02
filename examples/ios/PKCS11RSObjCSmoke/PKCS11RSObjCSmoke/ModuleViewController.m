@import PKCS11RS;

#import "ModuleViewController.h"

static NSString *const PKCS11RSConnectorURLKey = @"PKCS11RSConnectorURL";
static NSString *const PKCS11RSFallbackConnectorURL = @"http://plankan-9.duckdns.org:12345";
static NSString *const PKCS11RSSoftwareTokenName = @"iPhone smoke";
static NSString *const PKCS11RSSoftwareTokenModel = @"Software token";
static NSString *const PKCS11RSSoftwareTokenPIN = @"password";
static NSString *const PKCS11RSSoftwareX25519Label = @"iPhone smoke X25519";
static NSString *const PKCS11RSSoftwareX25519ID = @"iphone-smoke-x25519";
static NSString *const PKCS11RSSoftwareMLDSALabel = @"iPhone smoke ML-DSA-87";
static NSString *const PKCS11RSSoftwareMLDSAID = @"iphone-smoke-ml-dsa-87";
static NSString *const PKCS11RSSoftwareMLKEMLabel = @"iPhone smoke ML-KEM-1024";
static NSString *const PKCS11RSSoftwareMLKEMID = @"iphone-smoke-ml-kem-1024";
static NSString *const PKCS11RSHsmAuthPassword = @"password";
static NSString *const PKCS11RSPlatformCredentialName = @"iphone-qpernil-objc";
static NSString *const PKCS11RSPlatformCredentialLabel = @"iPhone qpernil Objective-C";
static const CK_ULONG PKCS11RSPlatformAuthenticationKeyID = 0x1005UL;
static const CK_ULONG PKCS11RSPlatformDomains = 0xffffUL;
enum {
    PKCS11RSInitialSlotCapacity = 10,
    PKCS11RSObjectBatchCapacity = 64,
    PKCS11RSAttributeCapacity = 1024,
    PKCS11RSX25519SecretLength = 32,
    PKCS11RSMLDSAMessageLength = 32,
    PKCS11RSMLKEMSecretLength = 32,
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

@interface PKCS11RSHsmAuthCredential : NSObject
@property(nonatomic, copy) NSString *label;
@property(nonatomic, copy) NSString *source;
@property(nonatomic) CK_ULONG algorithm;
@property(nonatomic) CK_ULONG retries;
@property(nonatomic) BOOL touchRequired;
- (NSString *)algorithmName;
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
@end


@implementation PKCS11RSObjectInspection
@end


@interface PKCS11RSObjectInventory : NSObject
@property(nonatomic, copy) NSArray<NSString *> *lines;
@property(nonatomic, copy) NSArray<PKCS11RSHsmAuthCredential *> *credentials;
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
    for (NSNumber *object in objects) {
        PKCS11RSObjectInspection *inspection =
            [self inspectObject:(CK_OBJECT_HANDLE)object.unsignedLongValue
                      inSession:session
                         source:source];
        [lines addObject:inspection.line];
        if (inspection.credential != nil) {
            [credentials addObject:inspection.credential];
        }
    }
    if (failure != nil) {
        [lines addObject:[NSString stringWithFormat:@"  %@", failure]];
    }

    PKCS11RSObjectInventory *inventory = [[PKCS11RSObjectInventory alloc] init];
    inventory.lines = lines;
    inventory.credentials = credentials;
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

- (CK_RV)findSoftwareKeyInSession:(CK_SESSION_HANDLE)session
                      objectClass:(CK_OBJECT_CLASS)objectClass
                           keyType:(CK_KEY_TYPE)keyType
                         identifier:(NSString *)identifierString
                           object:(CK_OBJECT_HANDLE *)object
                            found:(BOOL *)found {
    NSMutableData *identifier =
        [[identifierString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
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

- (CK_RV)generateSoftwarePostQuantumKeyPairInSession:(CK_SESSION_HANDLE)session
                                            mechanism:(CK_MECHANISM_TYPE)mechanismType
                                          parameterSet:(CK_ULONG)parameterSet
                                                 label:(NSString *)labelString
                                            identifier:(NSString *)identifierString
                                  publicUsageAttribute:(CK_ATTRIBUTE_TYPE)publicUsageAttribute
                                 privateUsageAttribute:(CK_ATTRIBUTE_TYPE)privateUsageAttribute
                                             publicKey:(CK_OBJECT_HANDLE *)publicKey
                                            privateKey:(CK_OBJECT_HANDLE *)privateKey {
    CK_BBOOL token = CK_TRUE;
    CK_BBOOL publicUsage = CK_TRUE;
    CK_BBOOL privateUsage = CK_TRUE;
    NSMutableData *identifier =
        [[identifierString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSMutableData *label =
        [[labelString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    CK_ATTRIBUTE publicAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, label.length},
        {CKA_ID, identifier.mutableBytes, identifier.length},
        {CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet)},
        {publicUsageAttribute, &publicUsage, sizeof(publicUsage)},
    };
    CK_ATTRIBUTE privateAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_LABEL, label.mutableBytes, label.length},
        {CKA_ID, identifier.mutableBytes, identifier.length},
        {privateUsageAttribute, &privateUsage, sizeof(privateUsage)},
    };
    CK_MECHANISM mechanism = {mechanismType, NULL_PTR, 0};
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

- (CK_RV)exerciseSoftwareMLDSAInSession:(CK_SESSION_HANDLE)session
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

- (CK_RV)softwareAttributeValueInSession:(CK_SESSION_HANDLE)session
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

- (CK_RV)exerciseSoftwareX25519InSession:(CK_SESSION_HANDLE)session
                                  publicKey:(CK_OBJECT_HANDLE)publicKey
                                 privateKey:(CK_OBJECT_HANDLE)privateKey
                         deriveMilliseconds:(double *)deriveMilliseconds
                            failedOperation:(NSString * __autoreleasing *)failedOperation {
    NSData *point = nil;
    CK_RV result = [self softwareAttributeValueInSession:session
                                                     key:publicKey
                                                    type:CKA_EC_POINT
                                                   value:&point];
    if (result != CKR_OK) {
        *failedOperation = @"C_GetAttributeValue(CKA_EC_POINT)";
        return result;
    }
    NSMutableData *publicPoint = [point mutableCopy];
    CK_ECDH1_DERIVE_PARAMS parameters = {
        CKD_NULL,
        0,
        NULL_PTR,
        publicPoint.length,
        publicPoint.mutableBytes,
    };
    CK_MECHANISM mechanism = {
        CKM_ECDH1_DERIVE,
        &parameters,
        sizeof(parameters),
    };
    CK_BBOOL token = CK_FALSE;
    CK_BBOOL sensitive = CK_FALSE;
    CK_BBOOL extractable = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_ULONG valueLength = PKCS11RSX25519SecretLength;
    CK_ATTRIBUTE secretAttributes[] = {
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE_LEN, &valueLength, sizeof(valueLength)},
    };
    CK_OBJECT_HANDLE derivedSecret = CK_INVALID_HANDLE;
    NSTimeInterval deriveStart = NSProcessInfo.processInfo.systemUptime;
    result = C_DeriveKey(session,
                         &mechanism,
                         privateKey,
                         secretAttributes,
                         sizeof(secretAttributes) / sizeof(secretAttributes[0]),
                         &derivedSecret);
    *deriveMilliseconds =
        (NSProcessInfo.processInfo.systemUptime - deriveStart) * 1000.0;
    if (result != CKR_OK) {
        *failedOperation = @"C_DeriveKey";
        return result;
    }

    NSData *secret = nil;
    result = [self softwareAttributeValueInSession:session
                                               key:derivedSecret
                                              type:CKA_VALUE
                                             value:&secret];
    if (result != CKR_OK) {
        C_DestroyObject(session, derivedSecret);
        *failedOperation = @"C_GetAttributeValue(derived secret)";
        return result;
    }
    NSMutableData *zeroSecret = [NSMutableData dataWithLength:PKCS11RSX25519SecretLength];
    if (secret.length != PKCS11RSX25519SecretLength || [secret isEqualToData:zeroSecret]) {
        C_DestroyObject(session, derivedSecret);
        *failedOperation = @"X25519 shared-secret validation";
        return CKR_GENERAL_ERROR;
    }
    result = C_DestroyObject(session, derivedSecret);
    *failedOperation = @"C_DestroyObject(derived secret)";
    return result;
}

- (CK_RV)exerciseSoftwareMLKEMInSession:(CK_SESSION_HANDLE)session
                               publicKey:(CK_OBJECT_HANDLE)publicKey
                              privateKey:(CK_OBJECT_HANDLE)privateKey
                        ciphertextLength:(CK_ULONG *)ciphertextLength
                 encapsulateMilliseconds:(double *)encapsulateMilliseconds
                 decapsulateMilliseconds:(double *)decapsulateMilliseconds
                         failedOperation:(NSString * __autoreleasing *)failedOperation {
    CK_MECHANISM mechanism = {CKM_ML_KEM, NULL_PTR, 0};
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
    result = [self softwareAttributeValueInSession:session
                                               key:encapsulatedSecret
                                              type:CKA_VALUE
                                             value:&first];
    if (result != CKR_OK) {
        *failedOperation = @"C_GetAttributeValue(encapsulated secret)";
        return result;
    }
    NSData *second = nil;
    result = [self softwareAttributeValueInSession:session
                                               key:decapsulatedSecret
                                              type:CKA_VALUE
                                             value:&second];
    if (result != CKR_OK) {
        *failedOperation = @"C_GetAttributeValue(decapsulated secret)";
        return result;
    }
    if (first.length != PKCS11RSMLKEMSecretLength || ![first isEqualToData:second]) {
        *failedOperation = @"ML-KEM shared-secret comparison";
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
        CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
        BOOL foundPublic = NO;
        BOOL foundPrivate = NO;
        CK_RV findPublic = [self findSoftwareKeyInSession:session
                                              objectClass:CKO_PUBLIC_KEY
                                                   keyType:CKK_EC_MONTGOMERY
                                                identifier:PKCS11RSSoftwareX25519ID
                                                   object:&publicKey
                                                    found:&foundPublic];
        CK_RV findPrivate = [self findSoftwareKeyInSession:session
                                               objectClass:CKO_PRIVATE_KEY
                                                    keyType:CKK_EC_MONTGOMERY
                                                 identifier:PKCS11RSSoftwareX25519ID
                                                    object:&privateKey
                                                     found:&foundPrivate];
        if (findPublic != CKR_OK) {
            failure = [NSString stringWithFormat:@"X25519 public-key search failed: %@",
                                                      PKCS11RSReturnValue(findPublic)];
        } else if (findPrivate != CKR_OK) {
            failure = [NSString stringWithFormat:@"X25519 private-key search failed: %@",
                                                      PKCS11RSReturnValue(findPrivate)];
        } else if (foundPublic && foundPrivate) {
            [prefix addObject:@"  X25519 keypair already present"];
        } else if (foundPublic || foundPrivate) {
            failure = @"X25519 keypair is incomplete";
        } else {
            NSTimeInterval generationStart = NSProcessInfo.processInfo.systemUptime;
            CK_RV generate = [self generateSoftwareX25519KeyPairInSession:session
                                                                 publicKey:&publicKey
                                                                privateKey:&privateKey];
            double generationMilliseconds =
                (NSProcessInfo.processInfo.systemUptime - generationStart) * 1000.0;
            if (generate == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  generated X25519 keypair in %.3f ms: public %lu, private %lu",
                    generationMilliseconds,
                    (unsigned long)publicKey,
                    (unsigned long)privateKey]];
            } else {
                failure = [NSString stringWithFormat:@"C_GenerateKeyPair(X25519) failed: %@",
                                                      PKCS11RSReturnValue(generate)];
            }
        }

        if (failure == nil) {
            double deriveMilliseconds = 0;
            NSString *failedOperation = nil;
            CK_RV exercise = [self exerciseSoftwareX25519InSession:session
                                                          publicKey:publicKey
                                                         privateKey:privateKey
                                                 deriveMilliseconds:&deriveMilliseconds
                                                    failedOperation:&failedOperation];
            if (exercise == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  X25519 self-agreement %.3f ms (32-byte shared secret)",
                    deriveMilliseconds]];
            } else {
                failure = [NSString stringWithFormat:@"%@(X25519) failed: %@",
                                                      failedOperation,
                                                      PKCS11RSReturnValue(exercise)];
            }
        }
    }

    if (failure == nil) {
        CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
        BOOL foundPublic = NO;
        BOOL foundPrivate = NO;
        CK_RV findPublic = [self findSoftwareKeyInSession:session
                                              objectClass:CKO_PUBLIC_KEY
                                                   keyType:CKK_ML_DSA
                                                identifier:PKCS11RSSoftwareMLDSAID
                                                   object:&publicKey
                                                    found:&foundPublic];
        CK_RV findPrivate = [self findSoftwareKeyInSession:session
                                               objectClass:CKO_PRIVATE_KEY
                                                    keyType:CKK_ML_DSA
                                                 identifier:PKCS11RSSoftwareMLDSAID
                                                    object:&privateKey
                                                     found:&foundPrivate];
        if (findPublic != CKR_OK) {
            failure = [NSString stringWithFormat:@"ML-DSA-87 public-key search failed: %@",
                                                      PKCS11RSReturnValue(findPublic)];
        } else if (findPrivate != CKR_OK) {
            failure = [NSString stringWithFormat:@"ML-DSA-87 private-key search failed: %@",
                                                      PKCS11RSReturnValue(findPrivate)];
        } else if (foundPublic && foundPrivate) {
            [prefix addObject:@"  ML-DSA-87 keypair already present"];
        } else if (foundPublic || foundPrivate) {
            failure = @"ML-DSA-87 keypair is incomplete";
        } else {
            NSTimeInterval generationStart = NSProcessInfo.processInfo.systemUptime;
            CK_RV generate = [self generateSoftwarePostQuantumKeyPairInSession:session
                                                                     mechanism:CKM_ML_DSA_KEY_PAIR_GEN
                                                                   parameterSet:CKP_ML_DSA_87
                                                                          label:PKCS11RSSoftwareMLDSALabel
                                                                     identifier:PKCS11RSSoftwareMLDSAID
                                                           publicUsageAttribute:CKA_VERIFY
                                                          privateUsageAttribute:CKA_SIGN
                                                                      publicKey:&publicKey
                                                                     privateKey:&privateKey];
            double generationMilliseconds =
                (NSProcessInfo.processInfo.systemUptime - generationStart) * 1000.0;
            if (generate == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  generated ML-DSA-87 keypair in %.3f ms: public %lu, private %lu",
                    generationMilliseconds,
                    (unsigned long)publicKey,
                    (unsigned long)privateKey]];
            } else {
                failure = [NSString stringWithFormat:@"C_GenerateKeyPair(ML-DSA-87) failed: %@",
                                                      PKCS11RSReturnValue(generate)];
            }
        }

        if (failure == nil) {
            CK_ULONG signatureLength = 0;
            double signMilliseconds = 0;
            double verifyMilliseconds = 0;
            NSString *failedOperation = nil;
            CK_RV exercise = [self exerciseSoftwareMLDSAInSession:session
                                                        publicKey:publicKey
                                                       privateKey:privateKey
                                                  signatureLength:&signatureLength
                                                 signMilliseconds:&signMilliseconds
                                               verifyMilliseconds:&verifyMilliseconds
                                                  failedOperation:&failedOperation];
            if (exercise == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  ML-DSA-87 sign %.3f ms, verify %.3f ms (%lu-byte signature)",
                    signMilliseconds,
                    verifyMilliseconds,
                    (unsigned long)signatureLength]];
            } else {
                failure = [NSString stringWithFormat:@"%@(ML-DSA-87) failed: %@",
                                                      failedOperation,
                                                      PKCS11RSReturnValue(exercise)];
            }
        }
    }

    if (failure == nil) {
        CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
        BOOL foundPublic = NO;
        BOOL foundPrivate = NO;
        CK_RV findPublic = [self findSoftwareKeyInSession:session
                                              objectClass:CKO_PUBLIC_KEY
                                                   keyType:CKK_ML_KEM
                                                identifier:PKCS11RSSoftwareMLKEMID
                                                   object:&publicKey
                                                    found:&foundPublic];
        CK_RV findPrivate = [self findSoftwareKeyInSession:session
                                               objectClass:CKO_PRIVATE_KEY
                                                    keyType:CKK_ML_KEM
                                                 identifier:PKCS11RSSoftwareMLKEMID
                                                    object:&privateKey
                                                     found:&foundPrivate];
        if (findPublic != CKR_OK) {
            failure = [NSString stringWithFormat:@"ML-KEM-1024 public-key search failed: %@",
                                                      PKCS11RSReturnValue(findPublic)];
        } else if (findPrivate != CKR_OK) {
            failure = [NSString stringWithFormat:@"ML-KEM-1024 private-key search failed: %@",
                                                      PKCS11RSReturnValue(findPrivate)];
        } else if (foundPublic && foundPrivate) {
            [prefix addObject:@"  ML-KEM-1024 keypair already present"];
        } else if (foundPublic || foundPrivate) {
            failure = @"ML-KEM-1024 keypair is incomplete";
        } else {
            NSTimeInterval generationStart = NSProcessInfo.processInfo.systemUptime;
            CK_RV generate = [self generateSoftwarePostQuantumKeyPairInSession:session
                                                                     mechanism:CKM_ML_KEM_KEY_PAIR_GEN
                                                                   parameterSet:CKP_ML_KEM_1024
                                                                          label:PKCS11RSSoftwareMLKEMLabel
                                                                     identifier:PKCS11RSSoftwareMLKEMID
                                                           publicUsageAttribute:CKA_ENCAPSULATE
                                                          privateUsageAttribute:CKA_DECAPSULATE
                                                                      publicKey:&publicKey
                                                                     privateKey:&privateKey];
            double generationMilliseconds =
                (NSProcessInfo.processInfo.systemUptime - generationStart) * 1000.0;
            if (generate == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  generated ML-KEM-1024 keypair in %.3f ms: public %lu, private %lu",
                    generationMilliseconds,
                    (unsigned long)publicKey,
                    (unsigned long)privateKey]];
            } else {
                failure = [NSString stringWithFormat:@"C_GenerateKeyPair(ML-KEM-1024) failed: %@",
                                                      PKCS11RSReturnValue(generate)];
            }
        }

        if (failure == nil) {
            CK_ULONG ciphertextLength = 0;
            double encapsulateMilliseconds = 0;
            double decapsulateMilliseconds = 0;
            NSString *failedOperation = nil;
            CK_RV exercise = [self exerciseSoftwareMLKEMInSession:session
                                                        publicKey:publicKey
                                                       privateKey:privateKey
                                                 ciphertextLength:&ciphertextLength
                                          encapsulateMilliseconds:&encapsulateMilliseconds
                                          decapsulateMilliseconds:&decapsulateMilliseconds
                                                  failedOperation:&failedOperation];
            if (exercise == CKR_OK) {
                [prefix addObject:[NSString stringWithFormat:
                    @"  ML-KEM-1024 encapsulate %.3f ms, decapsulate %.3f ms (%lu-byte ciphertext, shared secret matched)",
                    encapsulateMilliseconds,
                    decapsulateMilliseconds,
                    (unsigned long)ciphertextLength]];
            } else {
                failure = [NSString stringWithFormat:@"%@(ML-KEM-1024) failed: %@",
                                                      failedOperation,
                                                      PKCS11RSReturnValue(exercise)];
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

- (NSArray<NSString *> *)authenticatedInventoryForSlot:(CK_SLOT_ID)slot {
    NSString *username = @":*";

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
        [lines addObject:[NSString stringWithFormat:@"Automatic credential login %@: %@",
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
        [lines addObject:[NSString stringWithFormat:@"Automatic credential login %@: %@",
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
        [[@":*" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
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

    NSString *selector = [NSString stringWithFormat:@":%04lX@%@",
                                                     (unsigned long)PKCS11RSPlatformAuthenticationKeyID,
                                                     PKCS11RSPlatformCredentialName];
    NSMutableData *platformUsername =
        [[selector dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    result = C_LoginUser(session,
                         CKU_USER,
                         NULL_PTR,
                         0,
                         platformUsername.mutableBytes,
                         (CK_ULONG)platformUsername.length);
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
        [[@":*" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
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
        (void)[self inspectModuleIncludingSlots:NO];
        if (!_moduleInitialized) {
            return @"C_Initialize failed before provisioning.";
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
        if ([label hasPrefix:@"YubiHSM #"]) {
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
        (void)[self inspectModuleIncludingSlots:NO];
        if (!_moduleInitialized) {
            return @"C_Initialize failed before unprovisioning.";
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
        if ([label hasPrefix:@"YubiHSM #"]) {
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
    for (PKCS11RSSlotInventory *inventory in slotInventories) {
        [report appendFormat:@"\nSlot %lu: %@\n",
                             (unsigned long)inventory.slot,
                             inventory.slotDescription];
        [report appendFormat:@"  Token: %@\n", inventory.tokenLabel];
        [report appendFormat:@"  Serial: %@\n", inventory.serial];
        for (NSString *line in inventory.objects.lines) {
            [report appendFormat:@"%@\n", line];
        }

        if (inventory.yubiHsm) {
            NSArray<NSString *> *authenticated =
                [self authenticatedInventoryForSlot:inventory.slot];
            for (NSString *line in authenticated) {
                [report appendFormat:@"%@\n", line];
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
