// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
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
            const string keyId = "keyid";
            byte[] key = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(key);

            var serverSignatures= new List<byte[]>();
            var clientSignatures = new List<byte[]>();

            using var host = await CreateHost(serverSignatures, key, new Uri("https://localhost"));
            using var server = host.GetTestServer();

            var requestLoggingHandler = new RequestLoggingHandler(clientSignatures)
            {
                InnerHandler = server.CreateHandler()
            };

            var clientSigningPipeline = new SharedKey.SharedKeyHttpMessageHandler(keyId, key)
            {
                InnerHandler = requestLoggingHandler
            };

            using var httpClient = new HttpClient(clientSigningPipeline);
            HttpResponseMessage httpResponseMessage;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost/path/path with space/resource?a=1&a=2&b=1&A=3&c");
            {
                httpRequestMessage.Content = new StringContent("content");
                httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Single(clientSignatures);
            Assert.Single(serverSignatures);
            Assert.Equal(HttpStatusCode.OK, httpResponseMessage.StatusCode);

            Assert.Equal(clientSignatures[0], serverSignatures[0]);
        }

        [Theory]
        [InlineData("api", "", "/api")]
        [InlineData("api", "a=1", "/api\na:1")]
        [InlineData("api", "a=1&b=2", "/api\na:1\nb:2")]
        [InlineData("api", "a=1&b=2&a=3", "/api\na:1,3\nb:2")]
        [InlineData("api", "a=1&b=2&a=3&c", "/api\n:c\na:1,3\nb:2")]
        [InlineData("api", "c&a=1&b=2&a=3", "/api\n:c\na:1,3\nb:2")]
        [InlineData("api", "c", "/api\n:c")]
        [InlineData("api/", "a=1", "/api/\na:1")]
        public void VerifyResourceCanonicialization(string path, string query, string expected)
        {
            var httpMethod = new HttpMethod("GET");
            var requestUri = $"https://localhost/{path}?{query}";
            var httpRequestMessage = new HttpRequestMessage(httpMethod, requestUri);
            httpRequestMessage.Headers.Date = new DateTime(2022, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            var httpRequest = new DefaultHttpContext().Request;
            httpRequest.Headers.Add("Date", "Sat, 01 Jan 2022 00:00:00 GMT");
            httpRequest.Method = "GET";
            httpRequest.Protocol = "https";
            httpRequest.Host = new HostString("localhost");
            httpRequest.Path = $"/{path}";
            httpRequest.QueryString = new QueryString('?' + query);

            var canonicalizedHttpRequestMessageResource = CanonicalizationHelpers.CanonicalizeResource(httpRequestMessage);
            var canonicalizedHttpRequestResource = CanonicalizationHelpers.CanonicalizeResource(httpRequest);

            Assert.Equal(expected, canonicalizedHttpRequestResource);
            Assert.Equal(expected, canonicalizedHttpRequestMessageResource);
        }

        // Notes - media-type always defaults to "text/plain; charset=utf-8" so it cannot be null.
        const string TextContentType = "text/plain; charset=utf-8";

        [Theory]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("PUT", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "PUT\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", "gzip", null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\ngzip\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, "en-US", -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\nen-US\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, null, 5, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\n\n5\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, null, -1, "mgNkuembtIDdJeHwKEyFVQ==", null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\n\n0\nmgNkuembtIDdJeHwKEyFVQ==\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, null, -1, null, TextContentType, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\n\n0\n\ntext/plain; charset=utf-8\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sun, 02 Jan 2022 00:00:00 GMT", null, null, null, null, -1, -1, "GET\n\n\n0\n\n\nSun, 02 Jan 2022 00:00:00 GMT\n\n\n\n\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sun, 02 Jan 2022 00:00:00 GMT", "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, -1, -1, "GET\n\n\n0\n\n\nSun, 02 Jan 2022 00:00:00 GMT\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, "\"etag\"", null, null, -1, -1, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\"etag\"\n\n\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, "\"etag\"", null, -1, -1, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\"etag\"\n\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, "Sun, 02 Jan 2022 00:00:00 GMT", -1, -1, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\nSun, 02 Jan 2022 00:00:00 GMT\n\n")]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, 1, -1, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\nbytes=1-\n")]
        [InlineData("GET", null, null, -1, null, null, "Sat, 01 Jan 2022 00:00:00 GMT", null, null, null, null, 1, 2, "GET\n\n\n0\n\n\nSat, 01 Jan 2022 00:00:00 GMT\n\n\n\n\nbytes=1-2\n")]
        [InlineData("GET", "gzip", "en-UK", 0, null, TextContentType, "Sat, 01 Jan 2022 00:00:00 GMT", null, "\"etag\"", "\"etag\"", null, 1, 2, "GET\ngzip\nen-UK\n0\n\ntext/plain; charset=utf-8\nSat, 01 Jan 2022 00:00:00 GMT\n\n\"etag\"\n\"etag\"\n\nbytes=1-2\n")]
        public void VerifyRequestCanonicialization(
            string method,
            string contentEncoding,
            string contentLanguage,
            long contentLength,
            string contentMd5,
            string contentType,
            string date,
            string ifModifiedSince,
            string ifMatch,
            string ifNoneMatch,
            string ifUnmodifiedSince,
            long rangeLower,
            long rangeUpper,
            string expected)
        {
            const string requestUri = "https://localhost/api/fixed?a=b";

            var httpRequestMessage = new HttpRequestMessage(new HttpMethod(method), requestUri);

            httpRequestMessage.Headers.Date = DateTime.Parse(date, new CultureInfo("en-US") , DateTimeStyles.AdjustToUniversal);

            // We need content to create content headers, because Chris.
            if (contentType == null)
            {
                httpRequestMessage.Content = new ByteArrayContent(Array.Empty<byte>());
            }
            else if (contentType.Equals(TextContentType, StringComparison.OrdinalIgnoreCase))
            {
                httpRequestMessage.Content = new StringContent("", Encoding.UTF8, "text/plain");
            }
            else
            {
                throw new NotImplementedException("No code to parse that media type yet.");
            }

            var httpRequest = new DefaultHttpContext().Request;
            httpRequest.Method = method;
            httpRequest.Headers.Add(HeaderNames.Date, date);

            if (!string.IsNullOrEmpty(contentEncoding))
            {
                httpRequestMessage.Content = new ByteArrayContent(Array.Empty<byte>());
                httpRequestMessage.Content.Headers.ContentEncoding.Add(contentEncoding);
                httpRequest.Headers.Add(HeaderNames.ContentEncoding, contentEncoding);
            }

            if (!string.IsNullOrEmpty(contentLanguage))
            {
                httpRequestMessage.Content.Headers.ContentLanguage.Add(contentLanguage);
                httpRequest.Headers.Add(HeaderNames.ContentLanguage, contentLanguage);
            }

            if (contentLength != -1)
            {
                httpRequestMessage.Content.Headers.ContentLength = contentLength;
                httpRequest.ContentLength = contentLength;
            }

            if (!string.IsNullOrEmpty(contentMd5))
            {
                httpRequestMessage.Content.Headers.ContentMD5 = Convert.FromBase64String(contentMd5);
                httpRequest.Headers.Add(HeaderNames.ContentMD5, contentMd5);
            }

            if (!string.IsNullOrEmpty(contentType))
            {
                httpRequestMessage.Content.Headers.TryAddWithoutValidation(HeaderNames.ContentType, contentType);
                httpRequest.Headers.Add(HeaderNames.ContentType, contentType);

            }

            if (!string.IsNullOrEmpty(ifModifiedSince))
            {
                httpRequestMessage.Headers.TryAddWithoutValidation(HeaderNames.IfModifiedSince, ifModifiedSince);
                httpRequest.Headers.Add(HeaderNames.IfModifiedSince, ifModifiedSince);
            }

            if (!string.IsNullOrEmpty(ifMatch))
            {
                httpRequestMessage.Headers.IfMatch.Add(new System.Net.Http.Headers.EntityTagHeaderValue(ifMatch));
                httpRequest.Headers.Add(HeaderNames.IfMatch, ifMatch);
            }

            if (!string.IsNullOrEmpty(ifNoneMatch))
            {
                httpRequestMessage.Headers.IfNoneMatch.Add(new System.Net.Http.Headers.EntityTagHeaderValue(ifNoneMatch));
                httpRequest.Headers.Add(HeaderNames.IfNoneMatch, ifNoneMatch);
            }

            if (!string.IsNullOrEmpty(ifUnmodifiedSince))
            {
                httpRequestMessage.Headers.IfUnmodifiedSince = DateTime.Parse(ifUnmodifiedSince, new CultureInfo("en-US"), DateTimeStyles.AdjustToUniversal);
                httpRequest.Headers.Add(HeaderNames.IfUnmodifiedSince, ifUnmodifiedSince);
            }

            if (rangeLower != -1)
            {
                if (rangeUpper != -1)
                {
                    httpRequestMessage.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(rangeLower, rangeUpper);
                }
                else
                {
                    httpRequestMessage.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(rangeLower, null);
                }

                if (rangeUpper != -1)
                {
                    httpRequest.Headers.Add(HeaderNames.Range, $"bytes={rangeLower}-{rangeUpper}");
                }
                else
                {
                    httpRequest.Headers.Add(HeaderNames.Range, $"bytes={rangeLower}-");
                }
            }

            var canonicalizedHttpRequestMessageHeaders = CanonicalizationHelpers.CanonicalizeHeaders(httpRequestMessage);
            var canonicalizedHttpRequestHeaders = CanonicalizationHelpers.CanonicalizeHeaders(httpRequest);

            Assert.Equal(expected, canonicalizedHttpRequestHeaders);
            Assert.Equal(expected, canonicalizedHttpRequestMessageHeaders);
        }


        public class RequestLoggingHandler : DelegatingHandler
        {
            private readonly IList<byte[]> _requestSignatures;

            public RequestLoggingHandler(IList<byte[]> requestSignatures)
            {
                _requestSignatures = requestSignatures;
            }

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request == null)
                {
                    throw new ArgumentNullException(nameof(request));
                }

                AuthenticationHeaderValue authenticationHeaderValue = request.Headers.Authorization;

                if (authenticationHeaderValue != null)
                {
                    if (authenticationHeaderValue.Parameter != null)
                    {
                        string encodedSignature = authenticationHeaderValue.Parameter[(authenticationHeaderValue.Parameter.IndexOf(':', StringComparison.OrdinalIgnoreCase) + 1)..];
                        _requestSignatures.Add(Convert.FromBase64String(encodedSignature));
                    }
                }

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
