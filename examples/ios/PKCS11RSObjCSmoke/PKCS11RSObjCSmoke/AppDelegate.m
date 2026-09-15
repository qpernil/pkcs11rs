#import "AppDelegate.h"

#import "ModuleViewController.h"

@interface AppDelegate ()
@property(nonatomic, strong) ModuleViewController *viewController;
@end

@implementation AppDelegate

- (UIWindow *)connectWindowToScene:(UIWindowScene *)scene {
    if (self.viewController == nil) {
        self.viewController = [[ModuleViewController alloc] init];
    }
    UIWindow *window = [[UIWindow alloc] initWithWindowScene:scene];
    window.rootViewController = self.viewController;
    [window makeKeyAndVisible];
    return window;
}

- (void)applicationWillTerminate:(UIApplication *)application {
    (void)application;
    [self.viewController finalizeModule];
}

@end

@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation SceneDelegate

- (void)scene:(UIScene *)scene
    willConnectToSession:(UISceneSession *)session
                 options:(UISceneConnectionOptions *)connectionOptions {
    (void)session;
    (void)connectionOptions;
    if (![scene isKindOfClass:UIWindowScene.class]) {
        return;
    }
    AppDelegate *appDelegate = (AppDelegate *)UIApplication.sharedApplication.delegate;
    self.window = [appDelegate connectWindowToScene:(UIWindowScene *)scene];
}

@end
