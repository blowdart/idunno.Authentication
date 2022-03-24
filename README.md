# idunno.Authentication

[![Build Status](https://dev.azure.com/idunno-org/idunno.Authentication/_apis/build/status/blowdart.idunno.Authentication?branchName=dev)](https://dev.azure.com/idunno-org/idunno.Authentication/_build/latest?definitionId=1&branchName=master)

This repository contains a collection of various authentication mechanisms for ASP.NET Core, including

* [Basic Authentication](src/idunno.Authentication.Basic/)
* [Shared Key Authentication](src/idunno.Authentication.SharedKey/)
* [Certificate Authentication](src/idunno.Authentication.Certificate/)

Basic Authentication started as a demonstration of how to write authentication middleware and was not as something you would seriously consider using, but some people want Basic Authentication so here it is.

Certificate Authentication is a common request on the ASP.NET Core Security repo, so I wrote one for Core 2.x.
ASP.NET Core 3.0 took that as a starting point and includes Certificate Authentication as a [supported package](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/certauth?view=aspnetcore-3.1).

Basic Authentication is available for ASP.NET Core 2.1 and later.
Shared Key Authentication is available for ASP.NET Core 3.1 and later.
Certification Authentication is only targeted at ASP.NET Core 2.1.

This is **not** an official Microsoft project, this is an "In my spare time, entirely unsupported"™ effort.

## nuget packages

nuget packages are available.

| Authentication Type | nuget package                                                      |
|---------------------|--------------------------------------------------------------------|
| Basic               | https://www.nuget.org/packages/idunno.Authentication.Basic/        |
| SharedKey           | https://www.nuget.org/packages/idunno.Authentication.SharedKey/    |
| Certificate         | https://www.nuget.org/packages/idunno.Authentication.Certificate/  |

## Version History

| Version | Notes |
|---------|-------|
|2.3.0    | Added Shared key authentication |
|2.2.2    | Basic authentication now [multi-targets](https://github.com/blowdart/idunno.Authentication/issues/46) Core 2.1, 3.0, 3.1, .NET 5.0 and .NET 6.0 |
|2.2.2    | Basic authentication now [multi-targets](https://github.com/blowdart/idunno.Authentication/issues/46) Core 2.1, 3.0 and 3.1 |
|2.2.1    | Basic authentication now [returns a 421 request when a request is issued over HTTP](https://github.com/blowdart/idunno.Authentication/issues/44), unless AllowInsecureProtocol is set |
|2.2.0    | Basic authentication no longer throws exception when [invalid base64 data sent in authentication header](https://github.com/blowdart/idunno.Authentication/issues/40)<br>Added property for suppressing the WWW-Authenticate header [scheme](https://github.com/blowdart/idunno.Authentication/issues/36)Updated nuget license and package icon <br>
|2.1.1    | Added [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)<br>Changed library dependencies to remove demands for exact versions, following the [.NET Core open-source library guidance](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/)<br>nuget package is now signed
|2.1.0    | Added Certificate Authentication<br>Fixed Basic Authentication event handling<br>Packages are now Authenticode signed |


## What about older versions of ASP.NET Core?

Shared key authentication does not support ASP.NET Core 1.x or ASP.NET 2.x targetting .NET Framework.

Certificate Authentication is only available for ASP.NET Core 2.0. If you are using ASP.NET Core 3.1 or later please use the [supported package](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/certauth?view=aspnetcore-3.1).

Older versions of Basic Authentication are available in the appropriate branch. No nuget packages are available for ASP.NET Core 1.x.

| ASP.NET Core MVC Version | Branch                                                                        |
|--------------------------|-------------------------------------------------------------------------------|
| 1.1                      | [rel/1.1.1](https://github.com/blowdart/idunno.Authentication/tree/rel/1.1.1) |
| 1.0                      | [rel/1.0.0](https://github.com/blowdart/idunno.Authentication/tree/rel/1.0.0) |

## Notes

Each handler requires you to authenticate the credentials passed.
You are responsible for hardening this authentication and ensuring it performs under load.
