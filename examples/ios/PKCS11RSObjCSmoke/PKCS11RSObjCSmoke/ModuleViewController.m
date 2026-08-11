@import PKCS11RS;

#import "ModuleViewController.h"

static NSString *const PKCS11RSConnectorURLKey = @"PKCS11RSConnectorURL";
static NSString *const PKCS11RSFallbackConnectorURL = @"http://192.168.1.169:12345";
static NSString *const PKCS11RSSoftwareTokenName = @"iPhone smoke";
static NSString *const PKCS11RSSoftwareTokenPIN = @"password";

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

@implementation ModuleViewController {
    dispatch_queue_t _moduleQueue;
    BOOL _moduleInitialized;
    NSString *_connectorURL;
    NSString *_tokenStoragePath;
    UIButton *_refreshButton;
    UITextView *_outputView;
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
                        "Refresh runs synchronous PKCS #11 work on a serial background queue.";

    _refreshButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _refreshButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_refreshButton setTitle:@"Refresh" forState:UIControlStateNormal];
    [_refreshButton addTarget:self
                       action:@selector(refresh:)
             forControlEvents:UIControlEventTouchUpInside];

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
    _refreshButton.enabled = NO;
    [_refreshButton setTitle:@"Working…" forState:UIControlStateNormal];

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
                strongSelf->_refreshButton.enabled = YES;
                [strongSelf->_refreshButton setTitle:@"Refresh" forState:UIControlStateNormal];
            });
        }
    });
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

    if (!includeSlots) {
        [report appendString:@"\nTap Refresh to discover slots and inspect tokens.\n"];
        return report;
    }

    CK_ULONG slotCount = 0;
    result = C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
    [report appendFormat:@"C_GetSlotList(count): %@\n", PKCS11RSReturnValue(result)];
    if (result != CKR_OK) {
        return report;
    }

    NSMutableData *slotStorage = [[NSMutableData alloc] init];
    CK_ULONG capacity = slotCount;
    do {
        [slotStorage setLength:(NSUInteger)capacity * sizeof(CK_SLOT_ID)];
        result = C_GetSlotList(CK_TRUE, slotStorage.mutableBytes, &capacity);
    } while (result == CKR_BUFFER_TOO_SMALL);
    [report appendFormat:@"C_GetSlotList(data): %@\n", PKCS11RSReturnValue(result)];
    if (result != CKR_OK) {
        return report;
    }

    [report appendFormat:@"Present slots: %lu\n", (unsigned long)capacity];
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

        [report appendFormat:@"\nSlot %lu: %@\n",
                             (unsigned long)slots[index],
                             PKCS11RSFixedString(slotInformation.slotDescription,
                                                sizeof(slotInformation.slotDescription))];

        CK_TOKEN_INFO tokenInformation = {0};
        result = C_GetTokenInfo(slots[index], &tokenInformation);
        if (result == CKR_OK) {
            [report appendFormat:@"  Token: %@\n",
                                 PKCS11RSFixedString(tokenInformation.label,
                                                    sizeof(tokenInformation.label))];
            [report appendFormat:@"  Model: %@\n",
                                 PKCS11RSFixedString(tokenInformation.model,
                                                    sizeof(tokenInformation.model))];
            [report appendFormat:@"  Serial: %@\n",
                                 PKCS11RSFixedString(tokenInformation.serialNumber,
                                                    sizeof(tokenInformation.serialNumber))];
        } else {
            [report appendFormat:@"  C_GetTokenInfo: %@\n", PKCS11RSReturnValue(result)];
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
