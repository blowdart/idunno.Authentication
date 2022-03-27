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

## Configuring the client

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

## Configuring the server

For .NET 6 minimal APIs add a call to `build.Services.AddAuthentication()` in `program.cs` and then add the `SharedKey` handler, specifying a [key lookup function](#keyResolution) in options, 
and an [identity building function](#identityBuilding) in the OnValidateSharedKey event, before any call to `Services.AddRazorPages()`. For .NET 5 add the code in `ConfigureServices()` in `startup.cs`:

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

Ensure there is a call to `app.UseAuthentication()` before a call to `app.UseAuthorization()`. This is in the `Configure()` method in `startup.cs` for .NET 5.

```c#
app.UseRouting();

app.UseAuthorization();
app.UseAuthorization();

app.MapRazorPages();
```

Authorization is then enforced using the normal [ASP.NET authorization mechanisms](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/introduction?view=aspnetcore-6.0).

### <a name="keyResolution"></a>Key Resolution

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

### <a name="identityBuilding"></a>Building an identity

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

### Setting the maximum allowed message age

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

All authenticated requests for an endpoint protected with SharedKey authentication must include the standard HTTP `Authorization` header and a standard HTTP `Date` header.
If these headers are missing any requests to an endpoint that requires SharedKey authorization will fail.

### Specifying the Date header
All authorized requests must include the Coordinated Universal Time (UTC) timestamp in request. This timestamp must be included the standard HTTP/HTTPS Date header.

By default the server authentication hander will reject a request is with a 15 minute time period from the supplied timestamp. 
This guards against certain security attacks like replay attacks, whilst also allowing for clock skew between the client and server. 
When this check fails, the server returns response code 401 (Unauthorized).

### Specifying the Authorization header

To authenticate a request the request is canonicalized, then the canonicalized representation is signed using SHA256 HMAC with a key shared between the client and server.
This signature is attached to the HTTP request in the authorization header, with a scheme of `SharedKey` and the authorization parameters of an identifier for the key, followed by a colon (:) 
and then the calculated signature, encoded with [Base64](https://en.wikipedia.org/wiki/Base64). 

```
Authorization="[SharedKey] <Key Identifier>:<Signature>"
```

### Building a signature

To build a signature various properties of the request must be build into a representation of the request. The request representation is built by constructing 
a string from the following parts of the request, in the order listed, with each item followed by a newline character, separated by a newline (\n) character

* The HTTP verb for the request, in uppercase.
* The Content-Encoding header value for the request if present, otherwise an empty string.
* The Content-Language header value for the request if present, otherwise an empty string.
* The Content-Length header value for the request if present, otherwise an 0 followed by a newline (\n).
* The Content-MD5 header value for the request if present, which must be present if the request has content, otherwise an empty string.
* The Content-Type header value for the request if present, otherwise an empty string.
* The Date header value for the request if present, which much be present.
* The If-Modified-Since header value for the request if present, otherwise an empty string.
* The If-Match header value for the request if present, otherwise an empty string.
* The If-None-Match header value for the request if present, otherwise an empty string.
* The If-Unmodified-Since header value for the request if present, otherwise an empty string.
* The Range header value for the request if present, otherwise an empty string.

This representation is then appended with a canonicalized representation of the resource being requested.

The canonicalized resource is built by constructing a string as follows

* Start a string with the resource's encoded URI path, beginning with the forward slash (/) character, without query parameters
* Sort the query parameter names in alphabetical order, treating a query parameter that is not a key/value pair as having a null parameter name and coming 
first in any sorting
* For each query parameter name
  * Append a newline (\n) character to the resource string
  * Append the parameter name to the resource string, followed by a colon (:)
  * Append the parameter value to the resource string. If a parameter has multiple values the values should be sorted lexicographically and append as
  a comma separated list

Note that this formatting excludes the ability to use newline (\n) characters or commas in query parameters.

To summarize, a signature is calculated over the following representation of a request.

```
propertyStringToSign = VERB + "\n" +  
                       Content-Encoding + "\n" +  
                       Content-Language + "\n" +  
                       Content-Length + "\n" +  
                       Content-MD5 + "\n" +  
                       Content-Type + "\n" +  
                       Date + "\n" +  
                       If-Modified-Since + "\n" +  
                       If-Match + "\n" +  
                       If-None-Match + "\n" +  
                       If-Unmodified-Since + "\n" +  
                       Range + "\n" +  
                       CanonicalizedResource
```

For example a GET request made to https://localhost/path/resource?a=1&a=2&b=1&A=3&c with a request content of `Content`, made on 1st January at midnight would product the following representation

```
GET\n\n\n7\nmgNkuembtIDdJeHwKEyFVQ==\ntext/plain; charset=utf-8\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n/path/resource\n:c\na:1,2,3\nb:1
```

### Signing and encoding the signature

To produce a signature for use in the authorization header calculate the HMAC-SHA256 of the signature string, using the shared key known to both client and server, and finally 
Base64 encode the hash results.
