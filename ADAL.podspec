Pod::Spec.new do |s|
  s.name         = "ADAL"
  s.version      = "1.2.10-spark"
  s.summary      = "The ADAL SDK for iOS gives you the ability to add Azure Identity authentication to your application"

  s.description  = <<-DESC
                   The Azure Identity Library for Objective C. This library gives you the ability to add support for Work Accounts to your iOS and OS X applications with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft Azure AD, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support.
                   DESC
  s.homepage     = "https://github.com/AzureAD/azure-activedirectory-library-for-objc"
  s.license      = {
    :type => "Apache License, Version 2.0",
    :file => "LICENSE.txt"
  }
  s.authors      = { "Microsoft" => "nugetaad@microsoft.com" }
  s.social_media_url   = "https://twitter.com/azuread"
  s.platform     = :ios, "8.0"
  s.source       = {
    :git => "https://github.com/readdle/azure-activedirectory-library-for-objc.git",
    :tag => s.version.to_s
  }
  s.source_files = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.resources    = "ADALiOS/ADALiOS/*.storyboard"
  s.preserve_paths = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.requires_arc = true
end
