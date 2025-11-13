# idunno.Authentication

This repository contains a collection of various authentication mechanisms for ASP.NET Core, including

* [Basic Authentication](src/idunno.Authentication.Basic/)
* [Shared Key Authentication](src/idunno.Authentication.SharedKey/)

Basic Authentication started as a demonstration of how to write authentication middleware and was not as something you would seriously consider using, but apparently lots of you want Basic Authentication 
for apis, webhooks and other things so here it is.

Certificate Authentication was has been built into ASP.NET Core since 3.0. The code here is now EOL as ASP.NET Core 2.1 is out of support.

Shared Key Authentication is almost an implementation of the shared secret authentication Azure Blob Storage uses, with the Azure specific things like tenant identifier removed. If you're going to use
this in a real project you should have someone else look over the hashing used to reassure yourself (and me) that it doesn't have any mistakes.

As digest authentication typically requires passwords to be stored somewhere in plain text, or in an unsalted hash, there is no digest authentication implementation.

## ASP.NET Core versions supported

Basic Authentication is available for ASP.NET Core 2.3 and later.
Shared Key Authentication is available for ASP.NET Core 3.1 and later.

This is **not** an official Microsoft project, this is an "In my spare time, entirely unsupported"™ effort.

## nuget packages

nuget packages are available.

| Authentication Type | nuget package                                                      |
|---------------------|--------------------------------------------------------------------|
| Basic               | https://www.nuget.org/packages/idunno.Authentication.Basic/        |
| SharedKey           | https://www.nuget.org/packages/idunno.Authentication.SharedKey/    |

## Version History

| Version | Notes |
|---------|-------|
|3.0.0    | Added .NET 10 support for Basic and SharedKey authentication handlers. <br />
|         | Removed EOL targets from Basic Authentication and updated NetStandard2.0 to target [ASP.NET Core 2.3](https://devblogs.microsoft.com/dotnet/servicing-release-advisory-aspnetcore-23/). |
|         | Certificate authentication is no longer supported or updated as ASP.NET Core 2.1 is out of support. |
|2.4.0    | Added .NET 8 support for Basic and SharedKey, including deprecating the use of [ISystemClock](https://learn.microsoft.com/en-us/dotnet/core/compatibility/aspnet-core/8.0/isystemclock-obsolete). |
|2.3.1    | Added support for credential encoding character sets, latin1 and utf8 to Basic Authentication. |
|2.3.0    | Added Shared key authentication<br>Basic authentication now multi-targets ASP.NET Core 2.1, 3.0, 3.1, ASP.NET 5.0, 6.0 and 7.0 |
|2.2.3    | Basic authentication now multi-targets ASP.NET Core 2.1, 3.0, 3.1, .NET 5.0 and .NET 6.0 |
|2.2.2    | Basic authentication now [multi-targets](https://github.com/blowdart/idunno.Authentication/issues/46) ASP.NET Core 2.1, 3.0 and 3.1 |
|2.2.1    | Basic authentication now [returns a 421 request when a request is issued over HTTP](https://github.com/blowdart/idunno.Authentication/issues/44), unless AllowInsecureProtocol is set |
|2.2.0    | Basic authentication no longer throws exception when [invalid base64 data sent in authentication header](https://github.com/blowdart/idunno.Authentication/issues/40)<br>Added property for suppressing the WWW-Authenticate header [scheme](https://github.com/blowdart/idunno.Authentication/issues/36)<br>Updated nuget license and package icon <br>
|2.1.1    | Added [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)<br>Changed library dependencies to remove demands for exact versions, following the [.NET Core open-source library guidance](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/)<br>nuget package is now signed
|2.1.0    | Added Certificate Authentication<br>Fixed Basic Authentication event handling<br>Packages are now Authenticode signed |


## Notes

Each handler requires you to authenticate the credentials passed.
You are responsible for hardening this authentication and ensuring it performs under load.
