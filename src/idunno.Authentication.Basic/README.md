# idunno.Authentication.Basic

This project contains an implementation of [Basic Authentication](https://tools.ietf.org/html/rfc1945#section-11) for ASP.NET. 

It started as a demonstration of how to write authentication middleware and **not** as something you would seriously consider using, but enough of
you want to go with the world's worse authentication standard, so here we are. *You* are responsible for hardening it.

## Getting started

First acquire an HTTPS certificate (see Notes below). Apply it to your website. Remember to renew it when it expires, or go the
Lets Encrypt route and look like a phishing site.

In your web application add a reference to the package, then in the `ConfigureServices` method in `startup.cs` call
`app.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasic(...);` with your options, 
providing a delegate for `OnValidateCredentials` to validate any user name and password sent with requests and turn that information 
into an `ClaimsPrincipal`, set it on the `context.Principal` property and call `context.Success()`.

If you change your scheme name in the options for the basic authentication handler you need to change the scheme name in 
`AddAuthentication()` to ensure it's used on every request which ends in an endpoint that requires authorization.

You should also add `app.UseAuthentication();` in the `Configure` method, otherwise nothing will ever get called.

You can also specify the Realm used to isolate areas of a web site from one another.

For example;

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
            .AddBasic(options =>
            {
                options.Realm = "idunno";
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        if (context.Username == context.Password)
                        {
                            var claims = new[]
                            {
                                new Claim(
                                    ClaimTypes.NameIdentifier, 
                                    context.Username, 
                                    ClaimValueTypes.String, 
                                    context.Options.ClaimsIssuer),
                                new Claim(
                                    ClaimTypes.Name, 
                                    context.Username, 
                                    ClaimValueTypes.String, 
                                    context.Options.ClaimsIssuer)
                            };

                            context.Principal = new ClaimsPrincipal(
                                new ClaimsIdentity(claims, context.Scheme.Name));
                            context.Success();
                        }

                        return Task.CompletedTask;
                    }
                };
            });
    
    // All the other service configuration.
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseAuthentication();

    // All the other app configuration.
}
```

For .NET 6 minimal templates

```c#
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
    .AddBasic(options =>
    {
        options.Realm = "Basic Authentication";
        options.Events = new BasicAuthenticationEvents
        {
            OnValidateCredentials = context =>
            {
                if (context.Username == context.Password)
                {
                    var claims = new[]
                    {
                                    new Claim(ClaimTypes.NameIdentifier, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                                    new Claim(ClaimTypes.Name, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer)
                                };

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                    context.Success();
                }

                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();
```

and then, before calls to any app.Map functions

```c#
app.UseAuthentication();
app.UseAuthorization();
```

In the sample you can see that the delegate checks if the user name and password are identical. If they
are then it will consider that a valid login, create set of claims about the user, using the `ClaimsIssuer` from the handler options, 
then create an `ClaimsPrincipal` from those claims, using the `SchemeName` from the handler options, then finally call `context.Success();`
to show there's been a successful authentication.

Of course you'd never implement such a simple validation mechanism would you? No? Good. Have a cookie.

If you want to use Basic authentication within an Ajax application then it you may want to stop the browser prompting for a username and password. 
This prompt happens when a `WWWAuthenticate` header is sent, you can suppress this header by setting the `SuppressWWWAuthenticateHeader` flag on options.

The handler will throw an exception if wired up in a site not running on HTTPS and will refuse to respond to the challenge flow 
which ends up prompting the browser to ask for a user name and password. You can override this if you're a horrible person by
setting `AllowInsecureProtocol` to `true` in the handler options. If you do this you deserve everything you get. If you're 
using a non-interactive client, and are sending a user name and password to a server over HTTP the handler will not throw and
will process the authentication header because frankly it's too late, you've sent everything in plain text, what's the point?

## Accessing a service inside your delegate

For real functionality you will probably want to call a service registered in DI which talks to a database or other type of 
user store. You can grab your service by using the context passed into your delegates, like so

```c#
services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
  .AddBasic(options =>
  {
    options.Realm = "idunno";
    options.Events = new BasicAuthenticationEvents
    {
      OnValidateCredentials = context =>
      {
        var validationService =
          context.HttpContext.RequestServices.GetService<IUserValidationService>();
        if (validationService.AreCredentialsValid(context.Username, context.Password))
        {
          var claims = new[]
          {
            new Claim(ClaimTypes.NameIdentifier, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer),
            new Claim(ClaimTypes.Name, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer)
          };

          context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
          context.Success();
        }

        return Task.CompletedTask;
      }
    };
  })
```

## Using Basic Authentication in production

I'd never recommend you use basic authentication in production unless you're forced to in order to comply with a standard, but, if you must here are some ideas on how to harden your validation routine. 

1. In your `OnValidateCredentials` implementation keep a count of failed login attempts, and the IP addresses they come from.
2. Lock out accounts after X failed login attempts, where X is a count you feel is reasonable for your situation.
3. Implement the lock out so it unlocks after Y minutes. In case of repeated attacks increase Y.
4. Be careful when locking out your administration accounts. Have at least one admin account that is not exposed via basic auth, so an attacker cannot lock you out of your site just by sending an incorrect password.
5. Throttle attempts from an IP address, especially one which sends lots of incorrect passwords. Considering dropping/banning attempts from an IP address that appears to be under the control of an attacker. Only you can decide what this means, what consitutes legimate traffic varies from application to application.
6. Always use HTTPS. Redirect all HTTP traffic to HTTPS using `[RequireHttps]`. You can apply this to all of your site via a filter;

    ```c#
    services.Configure<MvcOptions>(options =>
    {
        options.Filters.Add(new RequireHttpsAttribute());
    });
    ```
7. Implement [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) and [preload](https://hstspreload.org/) 
   your site if your site is going to be accessed through a browser.
8. Reconsider your life choices, and look at using OAuth2 or OpenIDConnect instead.

## Support for older versions of ASP.NET Core

Older versions are available in the appropriate branch.

| ASP.NET Core MVC Version | Branch                                                           |
|--------------------------|------------------------------------------------------------------|
| 1.1                      | [rel/1.1.1](https://github.com/blowdart/idunno.Authentication/tree/rel/1.1.1) |
| 1.0                      | [rel/1.0.0](https://github.com/blowdart/idunno.Authentication/tree/rel/1.0.0) |

No nuget packages are available for older versions of ASP.NET Core.

## Notes

Basic Authentication sends credentials unencrypted. You should only use it over [HTTPS](https://en.wikipedia.org/wiki/HTTPS). 

It may also have performance impacts as credentials are sent and validated with every request. As you should not be storing passwords in clear text your validation procedure will have to hash and compare values
with every request, or cache results of previous hashes (which could lead to data leakage). 

Remember that hash comparisons should be time consistent to avoid [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).
