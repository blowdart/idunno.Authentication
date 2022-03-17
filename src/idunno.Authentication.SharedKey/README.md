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

### Client Code

To authenticate client requests an HttpMessageHandler must be configured for the [HttpClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient) sending the request.

For example

```c#
using idunno.Authentication.SharedKey;

var authenticationHandler = new SharedKeyHttpMessageHandler(keyID, keyAsBase64String)

using (var httpClient = new HttpClient(authenticationHandler))
{
    var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
    {
        httpRequestMessage.Content = new StringContent("myMessage");
        await httpClient.SendAsync(httpRequestMessage);
    };
}
```

There is an alternative constructor for SharedKeyHttpMessageHandler which takes the key as a byte array. If you are making calls from
an ASP.NET application you can configure the [HttpClientFactory](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/http-requests) to 
[add a handler for a named or typed client](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/http-requests?view=aspnetcore-6.0#configure-the-httpmessagehandler).

Signed messages have a validity period decided on by the server, if your HTTP request does not supply a date header one will be added automatically.

### Server Code

### How requests are canonicalised and signed
