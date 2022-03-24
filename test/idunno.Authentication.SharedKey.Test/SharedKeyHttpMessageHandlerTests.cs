// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace idunno.Authentication.SharedKey.Test
{
    [ExcludeFromCodeCoverage]
    public class SharedKeyHttpMessageHandlerTests
    {
        [Fact]
        public async Task AuthorizationHeaderIsAddedWithExpectedScheme()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.NotNull(requestLoggingHandler.Requests[0].Headers.Authorization);
            Assert.Equal("SharedKey", requestLoggingHandler.Requests[0].Headers.Authorization.Scheme);
        }

        [Fact]
        public async Task DateHaderIsAddedIfNotPresent()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.NotNull(requestLoggingHandler.Requests[0].Headers.Date);
        }

        [Fact]
        public async Task DateHaderIsNotAddedOrChangedIfAlreadyPresent()
        {
            var dateHeader = new DateTime(2000, 1, 1, 0, 0, 0);

            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Headers.Date = dateHeader;
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.Equal(dateHeader, requestLoggingHandler.Requests[0].Headers.Date);
        }

        [Fact]
        public async Task Md5IsAddedIfBodyIsPresentAndNotChunked()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.NotNull(requestLoggingHandler.Requests[0].Content.Headers.ContentMD5);

            using var md5 = MD5.Create();
            var expected = md5.ComputeHash(Encoding.ASCII.GetBytes("body"));
            Assert.Equal(expected, requestLoggingHandler.Requests[0].Content.Headers.ContentMD5);
        }

        [Fact]
        public async Task Md5IsNotAddedIfBodyIsPresentButChunked()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Headers.TransferEncodingChunked = true;
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.Null(requestLoggingHandler.Requests[0].Content.Headers.ContentMD5);
        }

        [Fact]
        public async Task ContentIsNotCreatedIfNoContentWasSpecified()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler("keyID", Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.Null(requestLoggingHandler.Requests[0].Content);
        }

        [Fact]
        public async Task AuthenticationHeaderSpecifiesTheKeyIdSupplied()
        {
            const string keyID = "keyId";

            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKey.SharedKeyHttpMessageHandler(keyID, Array.Empty<byte>())
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                };
            }

            Assert.Equal(1, requestLoggingHandler.Requests.Count);
            Assert.Equal(keyID, requestLoggingHandler.Requests[0].Headers.Authorization.Parameter[..keyID.Length]);
        }


        public class RequestLoggingHandler : DelegatingHandler
        {
            private readonly List<HttpRequestMessage> requests = new();

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                requests.Add(request);
                // We don't have an inner handler as we're just testing the client, so send an OK response.
                var response = new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK
                };
                return Task.FromResult(response);
            }

            public IReadOnlyList<HttpRequestMessage> Requests
            {
                get
                {
                    return requests.AsReadOnly();
                }
            }
        }
    }
}
