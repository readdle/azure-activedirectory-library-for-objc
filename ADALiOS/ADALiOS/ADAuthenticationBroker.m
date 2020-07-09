// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADALiOS.h"
#import "ADOAuth2Constants.h"
#import "UIApplication+ADExtensions.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationSettings.h"
#import "ADNTLMHandler.h"

NSString *const AD_FAILED_NO_CONTROLLER = @"The Application does not have a current ViewController";
NSString *const AD_FAILED_NO_RESOURCES  = @"The required resource bundle could not be loaded. Please read the ADALiOS readme on how to build your application with ADAL provided authentication UI resources.";
NSString *const AD_IPAD_STORYBOARD = @"ADAL_iPad_Storyboard";
NSString *const AD_IPHONE_STORYBOARD = @"ADAL_iPhone_Storyboard";

// Private interface declaration
@interface ADAuthenticationBroker ()
@end

// Implementation
@implementation ADAuthenticationBroker
{
    UIViewController* parentController;
    
    BOOL                               _ntlmSession;
    NSLock                             *_completionLock;
    
    void (^_completionBlock)( ADAuthenticationError *, NSURL *);
}

#pragma mark Shared Instance Methods

+ (ADAuthenticationBroker *)sharedInstance
{
    static ADAuthenticationBroker *broker     = nil;
    static dispatch_once_t          predicate;
    
    dispatch_once( &predicate, ^{
        broker = [[self allocPrivate] init];
    });
    
    return broker;
}

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    // [super alloc] calls to NSObject, and that calls [class allocWithZone:]
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

#pragma mark - Initialization

- (id)init
{
    self = [super init];
    
    if ( self )
    {
        _completionLock = [[NSLock alloc] init];
        _ntlmSession = NO;
    }
    
    return self;
}

#pragma mark - Private Methods

static NSString *_resourcePath = nil;

+ (NSString *)resourcePath
{
    return _resourcePath;
}

+ (void)setResourcePath:(NSString *)resourcePath
{
    _resourcePath = resourcePath;
}

// Retrive the bundle containing the resources for the library. May return nil, if the bundle
// cannot be loaded.
+ (NSBundle *)frameworkBundle
{
	return [NSBundle bundleForClass:[self class]];
}

+(NSString*) getStoryboardName
{
    return (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad)
    ? AD_IPAD_STORYBOARD
    : AD_IPHONE_STORYBOARD;
}

// Retrieve the current storyboard from the resources for the library. Attempts to use ADALiOS bundle first
// and if the bundle is not present, assumes that the resources are build with the application itself.
// Raises an error if both the library resources bundle and the application fail to locate resources.
+ (UIStoryboard *)storyboard: (ADAuthenticationError* __autoreleasing*) error
{
    NSBundle* bundle = [self frameworkBundle];//May be nil.
    if (!bundle)
    {
        //The user did not use ADALiOS.bundle. The resources may be manually linked
        //to the app by referencing the storyboards directly.
        bundle = [NSBundle mainBundle];
    }
    NSString* storyboardName = [self getStoryboardName];
    if ([bundle pathForResource:storyboardName ofType:@"storyboardc"])
    {
        //Despite Apple's documentation, storyboard with name actually throws, crashing
        //the app if the story board is not present, hence the if above.
        UIStoryboard* storyBoard = [UIStoryboard storyboardWithName:storyboardName bundle:bundle];
        if (storyBoard)
            return storyBoard;
    }
    
    ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MISSING_RESOURCES protocolCode:nil errorDetails:AD_FAILED_NO_RESOURCES];
    if (error)
    {
        *error = adError;
    }
    return nil;
}

-(NSURL*) addToURL: (NSURL*) url
     correlationId: (NSUUID*) correlationId
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@",
                                 [url absoluteString], OAUTH2_CORRELATION_ID_REQUEST_VALUE, [correlationId UUIDString]]];
}

#pragma mark - Public Methods

- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
parentController:(UIViewController *)parent
      webView:(WebViewType *)webView
   fullScreen:(BOOL)fullScreen
correlationId:(NSUUID *)correlationId
   completion:(ADBrokerCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(startURL);
    THROW_ON_NIL_ARGUMENT(endURL);
    THROW_ON_NIL_ARGUMENT(correlationId);
    THROW_ON_NIL_ARGUMENT(completionBlock)
    //AD_LOG_VERBOSE(@"Authorization", startURL.absoluteString);
    
    startURL = [self addToURL:startURL correlationId:correlationId];//Append the correlation id
    
    // Save the completion block
    _completionBlock = [completionBlock copy];
    
    _ntlmSession = [ADNTLMHandler startWebViewNTLMHandler:[endURL absoluteString] error:nil];
    if (_ntlmSession)
    {
        AD_LOG_INFO(@"Authorization UI", @"NTLM support enabled.");
    }

    //Error occurred above. Dispatch the callback to the caller:
    dispatch_async( [ADAuthenticationSettings sharedInstance].dispatchQueue, ^{
        ADAuthenticationError *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_NO_MAIN_VIEW_CONTROLLER
                                                                              protocolCode:nil
                                                                              errorDetails:AD_FAILED_NO_CONTROLLER];
        _completionBlock( error, nil );
    });
}

- (void)cancel
{
    
}

#pragma mark - Private Methods

- (void)dispatchCompletionBlock:(ADAuthenticationError *)error URL:(NSURL *)url
{
    // NOTE: It is possible that race between a successful completion
    //       and the user cancelling the authentication dialog can
    //       occur causing this method to be called twice. The race
    //       cannot be blocked at its root, and so this method must
    //       be resilient to this condition and should not generate
    //       two callbacks.
    [_completionLock lock];
    if (_ntlmSession)
    {
        [ADNTLMHandler endWebViewNTLMHandler];
    }
    if ( _completionBlock )
    {
        void (^completionBlock)( ADAuthenticationError *, NSURL *) = _completionBlock;
        _completionBlock = nil;
        
        dispatch_async( [ADAuthenticationSettings sharedInstance].dispatchQueue, ^{
            completionBlock( error, url );
        });
    }
    
    [_completionLock unlock];
}

@end
