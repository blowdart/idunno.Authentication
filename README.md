# idunno.Authentication

[![Build status](https://ci.appveyor.com/api/projects/status/afcip59il6a7axo0?svg=true)](https://ci.appveyor.com/project/blowdart/idunno-authentication)

This repository contains a collection of various authentication mechanisms for ASP.NET Core, including

* [Basic Authentication](src/idunno.Authentication.Basic/)
* [Certificate Authentication](src/idunno.Authentication.Certificate/)

Basic Authentication started as a demonstration of how to write authentication middleware and was not
as something you would seriously consider using, but some people want Basic Authentication so here it is.

Certificate Authentication is a common request on the ASP.NET Core Security repo, so I wrote one for Core 2.x. ASP.NET Core 3.0 took that as a starting point and includes Certificate Authentication as a [supported package](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/certauth?view=aspnetcore-3.1).

All packages are targeted at ASP.NET Core 2.1.

This is **not** an official Microsoft project, this is an "In my spare time, entirely unsupported"™ effort.

## nuget packages

nuget packages are available for the ASP.NET Core 2.0 versions of the authentication handlers.

| Authentication Type | Package Name                      | nuget link                                                        | Current Version |
|---------------------|-----------------------------------|-------------------------------------------------------------------|-----------------|
| Basic               | idunno.Authentication.Basic       | https://www.nuget.org/packages/idunno.Authentication.Basic/       | 2.1.1           |
| Certificate         | idunno.Authentication.Certificate | https://www.nuget.org/packages/idunno.Authentication.Certificate/ | 2.1.1           |



## Version History

| Version | Notes |
|---------|-------|
|2.2.0    | Basic auth no longer throws exception when [invalid base64 data sent in authentication header](https://github.com/blowdart/idunno.Authentication/issues/40)<br>Added property for suppressing the WWW-Authenticate header [scheme](https://github.com/blowdart/idunno.Authentication/issues/36)<br>Updated nuget license and package icon |
|2.1.1    | Added [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)<br>Changed library dependencies to remove demands for exact versions, following the [.NET Core open-source library guidance](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/)<br>nuget package is now signed
|2.1.0    | Added Certificate Authentication<br>Fixed Basic Authentication event handling<br>Packages are now Authenticode signed |


## What about older versions of ASP.NET Core?

Older versions of Basic Authentication are available in the appropriate branch. No nuget packages are available for ASP.NET Core 1.x.

Certificate Authentication is only available for ASP.NET Core 2.0. It will not be back ported to 1.x.

| ASP.NET Core MVC Version | Branch                                                                        |
|--------------------------|-------------------------------------------------------------------------------|
| 1.1                      | [rel/1.1.1](https://github.com/blowdart/idunno.Authentication/tree/rel/1.1.1) |
| 1.0                      | [rel/1.0.0](https://github.com/blowdart/idunno.Authentication/tree/rel/1.0.0) |

## Notes

Each handler requires you to authenticate the credentials passed.
You are responsible for hardening this authentication and ensuring it performs under load.
