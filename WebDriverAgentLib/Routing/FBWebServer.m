/**
 * Copyright (c) 2015-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#import "FBWebServer.h"

#import "FBHTTPServer.h"
#import "FBMjpegServer.h"
#import "FBTCPSocket.h"

#import "FBCommandHandler.h"
#import "FBCommandStatus.h"
#import "FBErrorBuilder.h"
#import "FBExceptionHandler.h"
#import "FBResponsePayload.h"
#import "FBRoute.h"
#import "FBRouteRequest.h"
#import "FBRuntimeUtils.h"
#import "FBSession.h"
#import "FBUnknownCommands.h"
#import "FBConfiguration.h"
#import "FBLogger.h"

#import <CommonCrypto/CommonDigest.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <string.h>
#import <sys/socket.h>

static NSString *const FBServerURLBeginMarker = @"ServerURLHere->";
static NSString *const FBServerURLEndMarker = @"<-ServerURLHere";
static NSString *const FBHardenedErrorDomain = @"WebDriverAgent.Hardened";
static const NSUInteger FBMinimumAuthTokenLength = 32;
static const NSUInteger FBMaximumAuthTokenLength = 128;
static const NSUInteger FBMinimumAllowedRouteCount = 15;
static const NSUInteger FBRejectedRequestLimit = 5;
static NSString *const FBHardenedLaunchTokenSHA256DefaultsKey = @"FBHardenedLaunchTokenSHA256";

static BOOL FBIsLoopbackBindAddress(NSString *address)
{
  if (0 == address.length) {
    return NO;
  }
  if (NSOrderedSame == [address caseInsensitiveCompare:@"localhost"]) {
    return YES;
  }
  const char *utf8 = address.UTF8String;
  if (NULL == utf8) {
    return NO;
  }
  struct in_addr ipv4;
  if (1 == inet_pton(AF_INET, utf8, &ipv4)) {
    uint32_t hostOrder = ntohl(ipv4.s_addr);
    return (hostOrder & 0xff000000u) == 0x7f000000u;
  }
  struct in6_addr ipv6;
  if (1 == inet_pton(AF_INET6, utf8, &ipv6)) {
    static const unsigned char loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return 0 == memcmp(ipv6.s6_addr, loopback, sizeof(loopback));
  }
  return NO;
}

static BOOL FBConstantTimeEqualStrings(NSString *left, NSString *right)
{
  NSData *leftData = [left dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
  NSData *rightData = [right dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
  NSUInteger leftLength = leftData.length;
  NSUInteger rightLength = rightData.length;
  NSUInteger maxLength = leftLength > rightLength ? leftLength : rightLength;
  const unsigned char *leftBytes = leftLength > 0 ? leftData.bytes : (const unsigned char *)"";
  const unsigned char *rightBytes = rightLength > 0 ? rightData.bytes : (const unsigned char *)"";
  unsigned char difference = (unsigned char)(leftLength == rightLength ? 0 : 1);
  for (NSUInteger index = 0; index < maxLength; index++) {
    unsigned char leftByte = index < leftLength ? leftBytes[index] : 0;
    unsigned char rightByte = index < rightLength ? rightBytes[index] : 0;
    difference |= (unsigned char)(leftByte ^ rightByte);
  }
  return 0 == difference;
}

static NSString *FBSHA256HexString(NSString *value)
{
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  const void *bytes = data.length > 0 ? data.bytes : "";
  CC_SHA256(bytes, (CC_LONG)data.length, digest);
  NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
    [hex appendFormat:@"%02x", digest[index]];
  }
  return hex;
}

static BOOL FBInterfaceNameIsPrivateTunnel(NSString *name)
{
  NSString *lower = name.lowercaseString;
  return [lower hasPrefix:@"lo"]
    || [lower hasPrefix:@"utun"]
    || [lower hasPrefix:@"tun"]
    || [lower hasPrefix:@"tap"]
    || [lower hasPrefix:@"ipsec"]
    || [lower hasPrefix:@"tailscale"];
}

static BOOL FBInterfaceNameIsSharedOrUnknown(NSString *name)
{
  return !FBInterfaceNameIsPrivateTunnel(name);
}

static BOOL FBSockaddrMatchesAddress(struct sockaddr *address, NSString *text)
{
  if (NULL == address || NULL == text.UTF8String) {
    return NO;
  }
  if (AF_INET == address->sa_family) {
    struct in_addr parsed;
    if (1 != inet_pton(AF_INET, text.UTF8String, &parsed)) {
      return NO;
    }
    return parsed.s_addr == ((struct sockaddr_in *)address)->sin_addr.s_addr;
  }
  if (AF_INET6 == address->sa_family) {
    struct in6_addr parsed;
    if (1 != inet_pton(AF_INET6, text.UTF8String, &parsed)) {
      return NO;
    }
    return 0 == memcmp(&parsed, &((struct sockaddr_in6 *)address)->sin6_addr, sizeof(parsed));
  }
  return NO;
}

// Non-loopback addresses are accepted only when every interface that owns the
// address is a private tunnel (utun, tun, tap, ipsec, tailscale, or lo).
static BOOL FBAddressIsOnlyOnPrivateTunnel(NSString *address)
{
  struct ifaddrs *interfaces = NULL;
  if (0 != getifaddrs(&interfaces)) {
    return NO;
  }
  BOOL sawTunnel = NO;
  BOOL sawOther = NO;
  for (struct ifaddrs *cursor = interfaces; NULL != cursor; cursor = cursor->ifa_next) {
    if (NULL == cursor->ifa_addr || NULL == cursor->ifa_name) {
      continue;
    }
    if (!FBSockaddrMatchesAddress(cursor->ifa_addr, address)) {
      continue;
    }
    NSString *name = [NSString stringWithUTF8String:cursor->ifa_name] ?: @"";
    if (FBInterfaceNameIsPrivateTunnel(name)) {
      sawTunnel = YES;
    }
    if (FBInterfaceNameIsSharedOrUnknown(name)) {
      sawOther = YES;
    }
  }
  freeifaddrs(interfaces);
  return sawTunnel && !sawOther;
}

static NSTimeInterval FBClampedWholeSeconds(NSString *raw, NSTimeInterval fallback, NSTimeInterval lower, NSTimeInterval upper)
{
  if (0 == raw.length) {
    return fallback;
  }
  for (NSUInteger index = 0; index < raw.length; index++) {
    unichar character = [raw characterAtIndex:index];
    if (character < '0' || character > '9') {
      return fallback;
    }
  }
  NSTimeInterval value = raw.doubleValue;
  if (value < lower) {
    return lower;
  }
  if (value > upper) {
    return upper;
  }
  return value;
}

static NSString *FBRouteAllowlistKey(FBRoute *route)
{
  NSString *path = route.path.length > 0 ? route.path : @"/";
  NSString *prefix = @"/session/:sessionID";
  if ([path isEqualToString:prefix]) {
    path = @"/";
  } else {
    NSString *prefixed = [prefix stringByAppendingString:@"/"];
    if ([path hasPrefix:prefixed]) {
      path = [path substringFromIndex:prefix.length];
    }
  }
  if (0 == path.length) {
    path = @"/";
  }
  return [NSString stringWithFormat:@"%@ %@", route.verb.uppercaseString, path];
}

// Paths are the route pattern with the /session/:sessionID prefix removed.
// Anything absent here is not registered, so it cannot run.
static NSSet<NSString *> *FBAllowedRouteKeys(void)
{
  static NSSet<NSString *> *keys;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    keys = [NSSet setWithArray:@[
      @"POST /session",
      @"GET /",
      @"DELETE /",
      @"GET /status",
      @"GET /screenshot",
      @"GET /source",
      @"GET /wda/accessibleSource",
      @"GET /window/size",
      @"GET /window/rect",
      @"GET /wda/screen",
      @"GET /wda/screens",
      @"GET /wda/activeAppInfo",
      @"POST /element",
      @"POST /elements",
      @"POST /element/:uuid/element",
      @"POST /element/:uuid/elements",
      @"GET /wda/element/:uuid/getVisibleCells",
      @"GET /element/active",
      @"GET /element/:uuid/enabled",
      @"GET /element/:uuid/rect",
      @"GET /element/:uuid/attribute/:name",
      @"GET /element/:uuid/text",
      @"GET /element/:uuid/displayed",
      @"GET /element/:uuid/selected",
      @"GET /element/:uuid/name",
      @"POST /element/:uuid/value",
      @"POST /element/:uuid/click",
      @"POST /element/:uuid/clear",
      @"GET /element/:uuid/screenshot",
      @"GET /screenshot/:uuid",
      @"GET /wda/element/:uuid/accessible",
      @"GET /wda/element/:uuid/accessibilityContainer",
      @"GET /element/:uuid/attribute/focused",
      @"POST /wda/element/:uuid/focuse",
      @"POST /wda/element/:uuid/swipe",
      @"POST /wda/swipe",
      @"POST /wda/element/:uuid/pinch",
      @"POST /wda/pinch",
      @"POST /wda/element/:uuid/rotate",
      @"POST /wda/rotate",
      @"POST /wda/element/:uuid/doubleTap",
      @"POST /wda/doubleTap",
      @"POST /wda/element/:uuid/twoFingerTap",
      @"POST /wda/twoFingerTap",
      @"POST /wda/element/:uuid/tapWithNumberOfTaps",
      @"POST /wda/tapWithNumberOfTaps",
      @"POST /wda/element/:uuid/touchAndHold",
      @"POST /wda/touchAndHold",
      @"POST /wda/element/:uuid/scroll",
      @"POST /wda/scroll",
      @"POST /wda/element/:uuid/scrollTo",
      @"POST /wda/element/:uuid/dragfromtoforduration",
      @"POST /wda/dragfromtoforduration",
      @"POST /wda/element/:uuid/pressAndDragWithVelocity",
      @"POST /wda/pressAndDragWithVelocity",
      @"POST /wda/element/:uuid/forceTouch",
      @"POST /wda/forceTouch",
      @"POST /wda/element/:uuid/tap",
      @"POST /wda/tap",
      @"POST /wda/keys",
      @"POST /wda/element/:uuid/keyboardInput",
      @"POST /actions",
      @"POST /wda/keyboard/dismiss",
      @"GET /alert/text",
      @"POST /alert/text",
      @"POST /alert/accept",
      @"POST /alert/dismiss",
      @"GET /wda/alert/buttons",
      @"GET /orientation",
      @"GET /rotation",
      @"GET /wda/deviceOrientation",
      @"POST /timeouts",
    ]];
  });
  return keys;
}

@interface FBWebServer ()
@property (nonatomic, strong) FBExceptionHandler *exceptionHandler;
@property (nonatomic, strong) FBHTTPServer *server;
@property (nonatomic, nullable) FBTCPSocket *screenshotsBroadcaster;
@property (nonatomic, nullable, strong) FBMjpegServer *mjpegServer;
@property (atomic, assign) BOOL keepAlive;
@property (nonatomic, nullable) NSTimer *idleTimer;
@property (nonatomic, nullable) NSTimer *lifetimeTimer;
@property (nonatomic, assign) NSTimeInterval idleTimeoutInterval;
@property (nonatomic, assign) NSTimeInterval maximumLifetimeInterval;
@property (nonatomic, assign) NSUInteger rejectedRequestCount;
@end

@implementation FBWebServer

- (void)dealloc
{
  [self stopScreenshotsBroadcaster];
}

+ (NSArray<Class<FBCommandHandler>> *)collectCommandHandlerClasses
{
  NSArray *handlersClasses = FBClassesThatConformsToProtocol(@protocol(FBCommandHandler));
  NSMutableArray *handlers = [NSMutableArray array];
  for (Class aClass in handlersClasses) {
    if ([aClass respondsToSelector:@selector(shouldRegisterAutomatically)]) {
      if (![aClass shouldRegisterAutomatically]) {
        continue;
      }
    }
    [handlers addObject:aClass];
  }
  return handlers.copy;
}

- (void)refuseToListen:(NSString *)message
{
  [FBLogger logFmt:@"Refusing to listen: %@", message];
  id<FBWebServerDelegate> delegate = self.delegate;
  if ([delegate respondsToSelector:@selector(webServer:didFailToStartWithError:)]) {
    NSError *error = [NSError errorWithDomain:FBHardenedErrorDomain
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: message}];
    [delegate webServer:self didFailToStartWithError:error];
  }
}

- (nullable NSString *)validatedAuthToken:(NSString * _Nullable * _Nullable)errorMessage
                               tokenHash:(NSString * _Nullable * _Nullable)tokenHash
{
  NSString *token = NSProcessInfo.processInfo.environment[@"WDA_AUTH_TOKEN"];
  if (token.length < FBMinimumAuthTokenLength || token.length > FBMaximumAuthTokenLength) {
    if (NULL != errorMessage) {
      *errorMessage = @"WDA_AUTH_TOKEN must be a new 32 to 128 character value before the listener will start. The value was not logged.";
    }
    return nil;
  }
  NSCharacterSet *forbidden = [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n"];
  BOOL hasWhitespace = NSNotFound != [token rangeOfCharacterFromSet:forbidden].location;
  BOOL hasControl = NSNotFound != [token rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location;
  if (hasWhitespace || hasControl) {
    if (NULL != errorMessage) {
      *errorMessage = @"WDA_AUTH_TOKEN contains whitespace or control characters. Choose another value. The value was not logged.";
    }
    return nil;
  }
  NSString *hash = FBSHA256HexString(token);
  NSString *previous = [NSUserDefaults.standardUserDefaults stringForKey:FBHardenedLaunchTokenSHA256DefaultsKey];
  if (previous.length > 0 && FBConstantTimeEqualStrings(previous, hash)) {
    if (NULL != errorMessage) {
      *errorMessage = @"WDA_AUTH_TOKEN matches the previous launch. Generate a new token for this start. The value was not logged.";
    }
    return nil;
  }
  if (NULL != tokenHash) {
    *tokenHash = hash;
  }
  return token;
}

- (nullable NSString *)validatedBindAddress:(NSString * _Nullable * _Nullable)errorMessage
{
  NSString *requested = [FBConfiguration.sharedInstance.bindingIPAddress stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
  if ([requested isEqualToString:@"0.0.0.0"] || [requested isEqualToString:@"::"] || [requested isEqualToString:@"::0"]) {
    if (NULL != errorMessage) {
      *errorMessage = @"The listener refuses the wildcard address. Unset USE_IP or set a loopback or private-tunnel address.";
    }
    return nil;
  }
  if (NSOrderedSame == [requested caseInsensitiveCompare:@"localhost"]) {
    return @"127.0.0.1";
  }
  if (FBIsLoopbackBindAddress(requested)) {
    return requested;
  }
  if (FBAddressIsOnlyOnPrivateTunnel(requested)) {
    return requested;
  }
  if (NULL != errorMessage) {
    *errorMessage = @"The listener only accepts loopback or an address that belongs only to a private tunnel interface. Port 8100 stays off shared LANs. Unset USE_IP or set it to 127.0.0.1.";
  }
  return nil;
}

- (void)resetIdleTimer
{
  if (![NSThread isMainThread]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      [self resetIdleTimer];
    });
    return;
  }
  [self.idleTimer invalidate];
  self.idleTimer = [NSTimer scheduledTimerWithTimeInterval:self.idleTimeoutInterval
                                                    target:self
                                                  selector:@selector(idleTimeoutFired)
                                                  userInfo:nil
                                                   repeats:NO];
}

- (void)invalidateLifecycleTimers
{
  if (![NSThread isMainThread]) {
    dispatch_sync(dispatch_get_main_queue(), ^{
      [self invalidateLifecycleTimers];
    });
    return;
  }
  [self.idleTimer invalidate];
  self.idleTimer = nil;
  [self.lifetimeTimer invalidate];
  self.lifetimeTimer = nil;
}

- (void)idleTimeoutFired
{
  [FBLogger log:@"Stopping the listener after the idle timeout. No further commands will be accepted."];
  [self stopServing];
}

- (void)lifetimeFired
{
  [FBLogger log:@"Stopping the listener because the maximum run lifetime was reached."];
  [self stopServing];
}

- (void)rejectedRequestWithReason:(NSString *)reason
{
  (void)reason;
  dispatch_async(dispatch_get_main_queue(), ^{
    if (!self.keepAlive) {
      return;
    }
    self.rejectedRequestCount += 1;
    if (self.rejectedRequestCount >= FBRejectedRequestLimit) {
      [FBLogger logFmt:@"Stopping the listener after %@ rejected requests.", @(self.rejectedRequestCount)];
      [self stopServing];
    }
  });
}

- (void)startServing
{
  [FBLogger logFmt:@"Built at %s %s", __DATE__, __TIME__];
  NSString *enabled = NSProcessInfo.processInfo.environment[@"WDA_ENABLE"];
  if (![enabled isEqualToString:@"1"]) {
    [FBLogger log:@"WebDriverAgent listener is off. No port was opened. Set WDA_ENABLE=1 in an unshared Xcode scheme to listen. See BUILD.md."];
    return;
  }

  NSString *tokenError = nil;
  NSString *tokenHash = nil;
  NSString *token = [self validatedAuthToken:&tokenError tokenHash:&tokenHash];
  if (nil == token) {
    [self refuseToListen:tokenError ?: @"WDA_AUTH_TOKEN was rejected."];
    return;
  }
  NSString *bindError = nil;
  NSString *bindAddress = [self validatedBindAddress:&bindError];
  if (nil == bindAddress) {
    [self refuseToListen:bindError ?: @"Bind address was rejected."];
    return;
  }

  self.exceptionHandler = [FBExceptionHandler new];
  self.keepAlive = YES;
  if (![self startHTTPServerWithToken:token bindAddress:bindAddress]) {
    self.keepAlive = NO;
    return;
  }
  if (tokenHash.length > 0) {
    [NSUserDefaults.standardUserDefaults setObject:tokenHash forKey:FBHardenedLaunchTokenSHA256DefaultsKey];
  }
  [FBLogger log:@"MJPEG screenshot streaming is disabled in this hardened build. Use the authenticated screenshot route."];
  self.idleTimeoutInterval = FBClampedWholeSeconds(NSProcessInfo.processInfo.environment[@"WDA_IDLE_TIMEOUT"], 120, 30, 900);
  self.maximumLifetimeInterval = FBClampedWholeSeconds(NSProcessInfo.processInfo.environment[@"WDA_MAX_LIFETIME"], 1800, 60, 3600);
  [FBLogger logFmt:@"Listener idle timeout is %@ seconds. Maximum lifetime is %@ seconds.",
    @((NSUInteger)self.idleTimeoutInterval), @((NSUInteger)self.maximumLifetimeInterval)];
  [self resetIdleTimer];
  self.lifetimeTimer = [NSTimer scheduledTimerWithTimeInterval:self.maximumLifetimeInterval
                                                        target:self
                                                      selector:@selector(lifetimeFired)
                                                      userInfo:nil
                                                       repeats:NO];

  NSRunLoop *runLoop = [NSRunLoop mainRunLoop];
  while (self.keepAlive &&
         [runLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]]);
  [self invalidateLifecycleTimers];
}

- (BOOL)startHTTPServerWithToken:(NSString *)token bindAddress:(NSString *)bindAddress
{
  self.server = [[FBHTTPServer alloc] init];
  self.server.sessionRequestKey = token;
  self.server.allowedHostAddress = bindAddress;
  __weak typeof(self) weakServer = self;
  self.server.acceptedCommandHandler = ^(NSString *method, NSString *path) {
    (void)method;
    (void)path;
    [weakServer resetIdleTimer];
  };
  self.server.rejectedCommandHandler = ^(NSString *reason) {
    [weakServer rejectedRequestWithReason:reason];
  };
  [self.server setRouteQueue:dispatch_get_main_queue()];
  [self.server setDefaultHeader:@"Server" value:@"WebDriverAgent/1.0"];
  [self.server setDefaultHeader:@"Cache-Control" value:@"no-store"];

  [NSNotificationCenter.defaultCenter addObserver:self
                                          selector:@selector(sessionWasKilled:)
                                              name:FBSessionWasKilledNotification
                                            object:nil];

  NSUInteger registeredRoutes = [self registerRouteHandlers:[self.class collectCommandHandlerClasses]];
  [self registerServerKeyRouteHandlers];
  if (registeredRoutes < FBMinimumAllowedRouteCount) {
    [NSNotificationCenter.defaultCenter removeObserver:self name:FBSessionWasKilledNotification object:nil];
    self.server = nil;
    [self refuseToListen:@"The hardened route allowlist matched too few handlers, so no port was opened."];
    return NO;
  }

  NSRange serverPortRange = FBConfiguration.sharedInstance.bindingPortRange;
  [self.server setInterface:bindAddress];
  [FBLogger logFmt:@"Binding the listener to %@", bindAddress];

  NSError *error;
  BOOL serverStarted = NO;

  for (NSUInteger index = 0; index < serverPortRange.length; index++) {
    NSInteger port = serverPortRange.location + index;
    [self.server setPort:(UInt16)port];

    serverStarted = [self attemptToStartServer:self.server onPort:port withError:&error];
    if (serverStarted) {
      break;
    }

    [FBLogger logFmt:@"Failed to start web server on port %ld with error %@", (long)port, [error description]];
  }

  if (!serverStarted) {
    [FBLogger logFmt:@"Last attempt to start web server failed with error %@", [error description]];
    [NSNotificationCenter.defaultCenter removeObserver:self name:FBSessionWasKilledNotification object:nil];
    self.server = nil;
    id<FBWebServerDelegate> delegate = self.delegate;
    if ([delegate respondsToSelector:@selector(webServer:didFailToStartWithError:)]) {
      [delegate webServer:self didFailToStartWithError:(NSError * _Nonnull)error];
      return NO;
    }
    abort();
  }

  [FBLogger logFmt:@"%@http://%@:%d%@", FBServerURLBeginMarker, bindAddress, [self.server port], FBServerURLEndMarker];
  return YES;
}

- (void)stopScreenshotsBroadcaster
{
  if (nil == self.screenshotsBroadcaster) {
    self.mjpegServer = nil;
    return;
  }

  id<FBTCPSocketDelegate> delegate = self.screenshotsBroadcaster.delegate;
  if ([(NSObject *)delegate respondsToSelector:@selector(stopStreaming)]) {
    [(FBMjpegServer *)delegate stopStreaming];
  }
  self.screenshotsBroadcaster.delegate = nil;
  [self.screenshotsBroadcaster stop];
  self.screenshotsBroadcaster = nil;
  self.mjpegServer = nil;
}

- (void)sessionWasKilled:(NSNotification *)notification
{
  FBSession *session = notification.object;
  if (![session isKindOfClass:FBSession.class]) {
    return;
  }
  // Same "invalid session id" shape a still-queued request would eventually get anyway, once
  // -routeQueue drains and FBRoute.decorateRequest: finds the session gone - just delivered now
  // instead of after however long the request would otherwise have been stuck waiting.
  NSString *message = [NSString stringWithFormat:@"Session %@ was deleted while this request was still pending", session.identifier];
  id<FBResponsePayload> payload = FBResponseWithStatus([FBCommandStatus noSuchDriverErrorWithMessage:message
                                                                                            traceback:nil]);
  RouteResponse *response = [RouteResponse new];
  [payload dispatchWithResponse:response];
  [self.server abandonPendingRequestsForSessionID:session.identifier withResponse:response];
}

- (void)stopServing
{
  [self invalidateLifecycleTimers];
  [NSNotificationCenter.defaultCenter removeObserver:self name:FBSessionWasKilledNotification object:nil];
  [FBSession.activeSession kill];
  [self stopScreenshotsBroadcaster];
  if (self.server.isRunning) {
    [self.server stop:NO];
  }
  self.server = nil;
  self.exceptionHandler = nil;
  self.keepAlive = NO;
}

- (BOOL)attemptToStartServer:(FBHTTPServer *)server onPort:(NSInteger)port withError:(NSError **)error
{
  server.port = (UInt16)port;
  NSError *innerError = nil;
  BOOL started = [server start:&innerError];
  if (!started) {
    if (!error) {
      return NO;
    }

    NSString *description = @"Unknown Error when Starting server";
    if ([innerError.domain isEqualToString:NSPOSIXErrorDomain] && innerError.code == EADDRINUSE) {
      description = [NSString stringWithFormat:@"Unable to start web server on port %ld", (long)port];
    }
    return
    [[[[FBErrorBuilder builder]
       withDescription:description]
      withInnerError:innerError]
     buildError:error];
  }
  return YES;
}

- (NSUInteger)registerRouteHandlers:(NSArray *)commandHandlerClasses
{
  NSUInteger registered = 0;
  NSUInteger skipped = 0;
  __weak typeof(self) weakSelf = self;
  for (Class<FBCommandHandler> commandHandler in commandHandlerClasses) {
    NSArray *routes = [commandHandler routes];
    for (FBRoute *route in routes) {
      NSString *allowlistKey = FBRouteAllowlistKey(route);
      if (![FBAllowedRouteKeys() containsObject:allowlistKey]) {
        skipped++;
        [FBLogger verboseLogFmt:@"Disabled route %@", allowlistKey];
        continue;
      }
      registered++;
      [self.server handleMethod:route.verb withPath:route.path standalone:route.isStandalone block:^(RouteRequest *request, RouteResponse *response) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (nil == strongSelf) {
          return;
        }
        NSDictionary *arguments = [NSJSONSerialization JSONObjectWithData:request.body options:NSJSONReadingMutableContainers error:NULL];
        FBRouteRequest *routeParams = [FBRouteRequest
          routeRequestWithURL:request.url
          parameters:request.params
          arguments:arguments ?: @{}
        ];

        @try {
          [route mountRequest:routeParams intoResponse:response];
        }
        @catch (NSException *exception) {
          [strongSelf handleException:exception forResponse:response];
        }
      }];
    }
  }
  [FBLogger logFmt:@"Hardened route allowlist registered %@ handlers and left %@ disabled.", @(registered), @(skipped)];
  return registered;
}

- (void)handleException:(NSException *)exception forResponse:(RouteResponse *)response
{
  [self.exceptionHandler handleException:exception forResponse:response];
}

- (void)registerServerKeyRouteHandlers
{
  [self.server handleMethod:@"GET" withPath:@"/health" standalone:YES block:^(RouteRequest *request, RouteResponse *response) {
    [response respondWithString:@"<!DOCTYPE html><html><title>Health Check</title><body><p>I-AM-ALIVE</p></body></html>"];
  }];

  __weak typeof(self) weakSelf = self;
  [self.server get:@"/wda/shutdown" withBlock:^(RouteRequest *request, RouteResponse *response) {
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (nil == strongSelf) {
      return;
    }
    [response respondWithString:@"Shutting down"];
    // Deferred so the "Shutting down" response is written to the client before
    // webServerDidRequestShutdown: tears down the server's socket out from under it.
    dispatch_async(dispatch_get_main_queue(), ^{
      [strongSelf.delegate webServerDidRequestShutdown:strongSelf];
    });
  }];

  [self registerRouteHandlers:@[FBUnknownCommands.class]];
}

@end
