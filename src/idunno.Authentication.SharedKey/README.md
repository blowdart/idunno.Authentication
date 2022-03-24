# idunno.Authentication.SharedKey
 
This project contains an implementation of Shared Key Authentication for ASP.NET. 
It was inspired by the Shared Key [implementation](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key) that Azure uses as one of its options for access to 
Blob, Table, Queue and File services. 

## Getting Started

The algorithm uses HMACSHA256 to produce for authentication, mixing a secret key with a canonicalized representation of the HTTP message. Any changes to the message or the hash results 
in a mismatch and failed authentication. HMACSHA256 keys can be any length, although the recommended size is 64 bytes. If the key provided is over 64 bytes it is hashed using SHA-256 
to produce a 64 byte key.

Using shared key authentication requires a key identifier and the key itself. The generation of the key identifier and key is outside the responsibility of the application rather than
this library. Typically the server application will generate this information for clients and supply the key identifier and a base64 representation of the key itself.

### Configuring the client

To authenticate client requests an [HttpMessageHandler(https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpmessagehandler) must be configured for the 
[HttpClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient) sending the request.

For example

```c#
using idunno.Authentication.SharedKey;

var authenticationHandler = new SharedKeyHttpMessageHandler(keyID, keyAsBase64String)
{
    InnerHandler = new HttpClientHandler()
};

using (var httpClient = new HttpClient(authenticationHandler))
{
    var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
    {
        httpRequestMessage.Content = new StringContent("myMessage");
        await httpClient.SendAsync(httpRequestMessage);
    };
}
```

There is an alternative constructor for `SharedKeyHttpMessageHandler` which takes the key as a byte array. 

If you are making calls from an ASP.NET application you can configure the [HttpClientFactory](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/http-requests) to 
[add a handler for a named or typed client](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/http-requests?view=aspnetcore-6.0#configure-the-httpmessagehandler).

### Configuring the server

For .NET 6 add a call to `build.Services.AddAuthentication()` and then add the `SharedKey` handler, specifying a [key lookup function](#keyResolution) in options, 
and an [identity building function](#identityBuilding) in the OnValidateSharedKey event, before any call to `Services.AddRazorPages()`:

```c#
builder.Services.AddAuthentication(SharedKeyAuthenticationDefaults.AuthenticationScheme)
    .AddSharedKey(options =>
    {
        options.KeyResolver = keyResolver.GetKey;
        options.Events = new SharedKeyAuthenticationEvents
        {
            OnValidateSharedKey = IdentityBuilder.OnValidateSharedKey
        };
    });
```

then after `app.UseRouting()` but before `app.MapRazorPages()` ensure there is a call to `app.UseAuthentication()` before a call to `app.UseAuthorization()`.

```c#
app.UseRouting();

app.UseAuthorization();
app.UseAuthorization();

app.MapRazorPages();
```

Authorization is then enforced using the normal [ASP.NET authorization mechanisms](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/introduction?view=aspnetcore-6.0).

#### <a name="keyResolution"></a>Key Resolution

Your key resolution function must have the signature `byte[] FunctionName(string keyId)`. If the keyID specified is unknown, return an empty array.

```c#
public byte[] GetKey(string keyId)
{
    // Look up the key identifier against your list of valid keys.
    if (!keys.ContainsKey(keyId))
    {
        return Array.Empty<byte>();
    }
    else
    {
        return keys[keyId];
    }
}
```

#### <a name="identityBuilding"></a>Building an identity

Like other ASP.NET authentication handlers you must provide a function to build a valid ClaimsIdentity from the information provided in the handler's context. 
This function is only called when the request has passed validation.

For the SharedKey handler function is specified in the `OnValidatedSharedKey` event. The `ValidateSharedKeyContext` contains a `KeyId` property you should use to 
retrieve user information for the holder of that key and use it to populate an authenticated `ClaimsPrincipal` which you then attach to the context. For example: 

```
    public static Task OnValidateSharedKey(ValidateSharedKeyContext context)
    {
        var claims = new[]
        {
            new Claim("keyId", context.KeyId, ClaimValueTypes.String, context.Options.ClaimsIssuer)
        };

        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
        context.Success();

        return Task.CompletedTask;
    }
```

Here we create a claims identity containing the key identifier that comes from the `ValidateSharedKeyContext`. A `ClaimsPrincipal` is then constructed 
using a `ClaimsIdentity` which contains the keyId claim and users the name of the authentication scheme from the context to show where the authenticated information
comes from. If you construct a `ClaimsIdentity` without this `AuthenticationType` parameter your principal is anonymous and authorization will fail.

Finally we call `context.Success()` to tell ASP.NET that yes, we have a principal to use. If you need to indicate a problem and fail the authentication 
call `context.Fail()`.

#### Setting the maximum allowed message age

All requests must be timestamped with the Coordinated Universal Time (UTC) timestamp for the request. The timestamp is contained in the standard HTTP Date header. 
If your client side request does not already contain a timestamp the `SharedKeyHttpMessageHandler` will add one. The server side `SharedKeyAuthenticationHandler` will ensure
that the inbound request is outside a configurable validity period, by default, 15 minutes. This validity period applies in both directions, allowing you to cater for clock skew as 
well as expiring messages.

To configure the validity period you can set the `MaximumMessageValidity` property on `SharedKeyAuthenticationHandler` options:

```c#
services.AddAuthentication()
  .AddSharedKey(options => options.MaximumMessageValidity = new TimeSpan(0,0,5));
```

## How requests are canonicalised and signed

All authenticated requests must include the standard HTTP `Authorization` header. If this header is not include any requests to an endpoint that requires authorization will fail.

To authenticate a request it is signed with a key shared between the client and server and this signature is attached to the HTTP request. On the server the signature is validated, and 
a user identity is created for the request which can then be used in the standard [ASP.NET authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/introduction) process.