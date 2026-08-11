#import "AppDelegate.h"

#import "ModuleViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary<UIApplicationLaunchOptionsKey, id> *)launchOptions {
    (void)application;
    (void)launchOptions;

    ModuleViewController *viewController = [[ModuleViewController alloc] init];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = viewController;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)applicationWillTerminate:(UIApplication *)application {
    (void)application;
    ModuleViewController *viewController =
        (ModuleViewController *)self.window.rootViewController;
    [viewController finalizeModule];
}

@end
