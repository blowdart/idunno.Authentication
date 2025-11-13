// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace idunno.Authentication.SharedKey.Test
{
    [ExcludeFromCodeCoverage]
    public class SharedKeyHttpMessageHandlerTests
    {
        [Fact]
        public async Task AuthorizationHeaderIsAddedWithExpectedScheme()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
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

            Assert.Single(requestLoggingHandler.Requests);

            var request = requestLoggingHandler.Requests[0];
            Assert.NotNull(request.Headers.Authorization);

            Assert.Equal("SharedKey", request.Headers.Authorization.Scheme);
        }

        [Fact]
        public async Task DateHeaderIsAddedIfNotPresent()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
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

            Assert.Single(requestLoggingHandler.Requests);
            Assert.NotNull(requestLoggingHandler.Requests[0].Headers.Date);
        }

        [Fact]
        public async Task DateHeaderIsNotAddedOrChangedIfAlreadyPresent()
        {
            var dateHeader = new DateTime(2000, 1, 1, 0, 0, 0);

            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
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

            Assert.Single(requestLoggingHandler.Requests);
            Assert.Equal(dateHeader, requestLoggingHandler.Requests[0].Headers.Date);
        }

        [Fact]
        public async Task Md5IsAddedIfBodyIsPresentAndNotChunked()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
            {
                InnerHandler = requestLoggingHandler
            };

            using (var httpClient = new HttpClient(handlerPipeline))
            {
                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
                {
                    httpRequestMessage.Content = new StringContent("body");
                    await httpClient.SendAsync(httpRequestMessage);
                }
                ;
            }

            Assert.Single(requestLoggingHandler.Requests);

            var request = requestLoggingHandler.Requests[0];
            Assert.NotNull(request);
            Assert.NotNull(request.Content);
            Assert.NotNull(request.Content.Headers);
            Assert.NotNull(request.Content.Headers.ContentMD5);

            var expected = MD5.HashData(Encoding.ASCII.GetBytes("body"));
            Assert.Equal(expected, request.Content.Headers.ContentMD5);
        }

        [Fact]
        public async Task Md5IsNotAddedIfBodyIsPresentButChunked()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
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

            Assert.Single(requestLoggingHandler.Requests);

            var request = requestLoggingHandler.Requests[0];
            Assert.NotNull(request);
            Assert.NotNull(request.Content);
            Assert.NotNull(request.Content.Headers);
            Assert.Null(request.Content.Headers.ContentMD5);
        }

        [Fact]
        public async Task ContentIsNotCreatedIfNoContentWasSpecified()
        {
            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler("keyID", [])
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

            Assert.Single(requestLoggingHandler.Requests);

            Assert.Null(requestLoggingHandler.Requests[0].Content);
        }

        [Fact]
        public async Task AuthenticationHeaderSpecifiesTheKeyIdSupplied()
        {
            const string keyID = "keyId";

            var requestLoggingHandler = new RequestLoggingHandler();

            var handlerPipeline = new SharedKeyHttpMessageHandler(keyID, [])
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

            Assert.Single(requestLoggingHandler.Requests);

            var request = requestLoggingHandler.Requests[0];
            Assert.NotNull(request);
            Assert.NotNull(request.Headers.Authorization);
            Assert.NotNull(request.Headers.Authorization.Parameter);

            Assert.Equal(keyID, request.Headers.Authorization.Parameter[..keyID.Length]);
        }

        public class RequestLoggingHandler : DelegatingHandler
        {
            private readonly List<HttpRequestMessage> requests = [];

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
