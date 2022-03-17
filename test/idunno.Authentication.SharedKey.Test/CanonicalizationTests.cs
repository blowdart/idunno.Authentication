// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace idunno.Authentication.SharedKey.Test
{
#if (DEBUG)
    [ExcludeFromCodeCoverage]
    // As Chris, in his infinite wisdom decided that HttpMessage wasn't good enough for ASP.NET inbound requests we ought to validate
    // expectations around the mapping of HttpMessage to HttpRequestMessage. Thanks @Tratcher!
    // These checks will only run in debug compiles as they're validating internal APIs, and debug wrapping allows us to avoid unnecessary
    // public classes and friend assembly attributes.
    public class CanonicalizationTests
    {
        [Fact]
        public async Task VerifyHttpMessageHasTheSameSignatureAsTheCorrespondingHttpRequest()
        {
            byte[] key = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(key);

            var serverSignatures= new List<byte[]>();
            var clientSignatures = new List<byte[]>();

            using (var host = await CreateHost(serverSignatures, key))
            {
                using var server = host.GetTestServer();

                var requestLoggingHandler = new RequestLoggingHandler(clientSignatures, key)
                {
                    InnerHandler = server.CreateHandler()
                };

                using var httpClient = new HttpClient(requestLoggingHandler);
                HttpResponseMessage httpResponseMessage;
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost/path/resource?a=1&a=2&b=1&A=3&c");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);
                };

                Assert.Single(clientSignatures);
                Assert.Single(serverSignatures);
                Assert.Equal(HttpStatusCode.OK, httpResponseMessage.StatusCode);

                //
                Assert.Equal(clientSignatures[0], serverSignatures[0]);
            }
        }

        public class RequestLoggingHandler : DelegatingHandler
        {
            private readonly IList<byte[]> _requestSignatures;
            private readonly byte[] _key;

            public RequestLoggingHandler(IList<byte[]> requestSignatures, byte[] key)
            {
                _requestSignatures = requestSignatures;
                _key = key;
            }

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _requestSignatures.Add(SharedKeySignature.Calculate(request, _key));
                return base.SendAsync(request, cancellationToken);
            }
        }

        private static async Task<IHost> CreateHost(
            IList<byte[]> requestSignatures,
            byte[] key,
            Uri baseAddress = null)
        {
            var host = new HostBuilder()
                 .ConfigureWebHost(builder =>
                     builder.UseTestServer()
                        .Configure(app =>
                        {
                            app.Run(async (context) =>
                            {
                                requestSignatures.Add(SharedKeySignature.Calculate(context.Request, key));
                                var response = context.Response;
                                response.StatusCode = (int)HttpStatusCode.OK;
                                response.ContentType = "text/plain";
                                await response.WriteAsync("OK");
                            });
                        })
                 ).Build();

            await host.StartAsync();

            var server = host.GetTestServer();
            server.BaseAddress = baseAddress;
            return host;
        }

    }
#endif
}
