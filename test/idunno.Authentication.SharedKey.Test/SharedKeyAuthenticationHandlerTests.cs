// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;

namespace idunno.Authentication.SharedKey.Test
{
    [ExcludeFromCodeCoverage]
    public class SharedKeyAuthenticationHandlerTests
    {
        private const string AuthenticationHeaderName = "WWW-Authenticate";
        private const string SharedKeyAuthenticateSchemeName = "SharedKey";

        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddSharedKey();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(SharedKeyAuthenticationDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("SharedKeyAuthenticationHandler", scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task NoAuthorizationHeaderReturnsUnauthorized()
        {
            using var host = await CreateHost(o => { });
            using var server = host.GetTestServer();
            var response = await server.CreateClient().GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizationHeaderWithoutMatchingSchemeReturnsUnauthorized()
        {
            using var host = await CreateHost(o => { });
            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("bogus", "bogus");
            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task EmptyAuthorizationHeaderReturnsUnauthorized()
        {
            using var host = await CreateHost(o => { });
            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Add(AuthenticationHeaderName, value: null);
            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizationHeaderWithCurrentSchemeButNoValueReturnsUnauthorized()
        {
            using var host = await CreateHost(o => { });
            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(SharedKeyAuthenticateSchemeName, null);
            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); ;
        }

        [Fact]
        public async Task AuthorizedRequestWithUnknownKeyIdReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
            });

            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(SharedKeyAuthenticateSchemeName, knownKeyId + ":");

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithKnownKeyIdButInvalidBase64SignatureReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [0xDE, 0xAD, 0xBE, 0xEF];
                    }
                };
            });

            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(SharedKeyAuthenticateSchemeName, knownKeyId + ": XXX");

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithKnownKeyIdButNoSeparatorReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
            });

            using var server = host.GetTestServer();
            using var httpClient = server.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(SharedKeyAuthenticateSchemeName, knownKeyId);

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithKnownKeyIdAndMatchingKeyAndNoBodyReturnsOk()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithKnownKeyIdAndMatchingKeyAndBodyReturnsOk()
        {
            const string knownKeyId = "keyId";
            const string keyClaimName = "KeyIdClaim";

            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            keyClaimName,
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            XElement? responseAsXml = null;
            if (response.Content != null &&
                response.Content.Headers.ContentType != null &&
                response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                responseAsXml = XElement.Parse(responseContent);
            }

            Assert.NotNull(responseAsXml);
            var claimValue = responseAsXml.Elements("claim").Where(claim => claim.Attribute("Type")!.Value == keyClaimName);
            Assert.Single(claimValue);
            Assert.Equal(knownKeyId, claimValue.First().Value);
        }

        [Fact]
        public async Task AuthorizedRequestWithKnownKeyIdAndMatchingKeyAndChangedBodyReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler(async (request) =>
                {
                    ArgumentNullException.ThrowIfNull(request.Content);
                    _ = await request.Content.ReadAsStringAsync();
                    request.Content = new StringContent("newRequestBody");
                })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithNullDateHeaderReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                request.Headers.Date = null;
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithInvalidDateHeaderReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                request.Headers.Remove(HeaderNames.Date);
                request.Headers.TryAddWithoutValidation(HeaderNames.Date, "NotAValidDate");
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWhichIsTooOldReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                request.Headers.Remove(HeaderNames.Date);
                request.Headers.Date = DateTime.UtcNow - new TimeSpan(1, 0, 0);
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWhichIsTooFarInTheFutureReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                request.Headers.Remove(HeaderNames.Date);
                request.Headers.Date = DateTime.UtcNow + new TimeSpan(1, 0, 0);
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }


        [Fact]
        public async Task AuthorizedRequestWithContentAndNoMd5ReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Content);
                request.Content.Headers.Remove(HeaderNames.ContentMD5);
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithContentAndMismatchedMd5ReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler(async (request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Content);
                ArgumentNullException.ThrowIfNull(request.Content.Headers);
                ArgumentNullException.ThrowIfNull(request.Content.Headers.ContentMD5);

                await request.Content.ReadAsStringAsync();
                // If we change the content the MD5 header gets removed, so we need to mutate the MD5 header
                byte[] mutatedMD5Value = request.Content.Headers.ContentMD5;
                if (mutatedMD5Value[0] < 255)
                {
                    mutatedMD5Value[0]++;
                }
                else
                {
                    mutatedMD5Value[0] = 0x00;
                }
                request.Content.Headers.ContentMD5 = mutatedMD5Value;
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithContentAndInvalidBase64Md5ReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Content);

                request.Content.Headers.Remove(HeaderNames.ContentMD5);
                request.Content.Headers.TryAddWithoutValidation(HeaderNames.ContentMD5, "NotBase64");
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Theory]
        [InlineData("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")]
        [InlineData("If-Match", "\"etag\"")]
        [InlineData("If-None-Match", "\"etag\"")]
        [InlineData("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")]
        [InlineData("Range", "1-")]
        public async Task MutatingARequestThatAffectsACanonicalizedRequestHeaderReturnsUnauthorized(string headerName, string value)
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                request.Headers.Remove(headerName);
                request.Headers.TryAddWithoutValidation(headerName, value);
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Theory]
        [InlineData("Content-Encoding", "compress")]
        [InlineData("Content-Language", "en-UK")]
        [InlineData("Content-Type", "not/valid")]
        public async Task MutatingARequestThatAffectsACanonicalizedContentHeaderReturnsUnauthorized(string headerName, string value)
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.MaximumMessageValidity = new TimeSpan(0, 0, 15, 0);
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();

            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Content);

                request.Content.Headers.Remove(headerName);
                request.Content.Headers.TryAddWithoutValidation(headerName, value);
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            HttpResponseMessage response;
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://localhost");
            {
                httpRequestMessage.Content = new StringContent("body");
                response = await httpClient.SendAsync(httpRequestMessage);
            };

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithUnresolvedKeyIdentifierReturningNullReturnsUnauthorized()
        {
            const string KeyId = "keyId";
            byte[] keyForKeyId = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(keyForKeyId);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    return null;
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(KeyId, keyForKeyId)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthorizedRequestWithUnresolvedKeyIdentifierReturningAnEmptyArrayReturnsUnauthorized()
        {
            const string KeyId = "keyId";
            byte[] keyForKeyId = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(keyForKeyId);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    return [];
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(KeyId, keyForKeyId)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidAuthorizationFormatReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] keyForKeyId = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(keyForKeyId);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return keyForKeyId;
                    }
                    else
                    {
                        return [];
                    }
                };
            });

            using var server = host.GetTestServer();
            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Headers.Authorization);
                ArgumentNullException.ThrowIfNull(request.Headers.Authorization.Parameter);

                var existingAuthenticationHeaderScheme = request.Headers.Authorization.Scheme;
                var existingAuthenticationHeaderValue = request.Headers.Authorization.Parameter;
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(existingAuthenticationHeaderScheme,
                                                                                                      existingAuthenticationHeaderValue.Replace(":", string.Empty, StringComparison.OrdinalIgnoreCase));
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, keyForKeyId)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task MissingSignatureReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] keyForKeyId = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(keyForKeyId);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return keyForKeyId;
                    }
                    else
                    {
                        return [];
                    }
                };
            });

            using var server = host.GetTestServer();
            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Headers.Authorization);

                var existingAuthenticationHeaderScheme = request.Headers.Authorization.Scheme;
                var existingAuthenticationHeaderValue = request.Headers.Authorization.Parameter;
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(existingAuthenticationHeaderScheme,
                                                                                                      "KeyId:");
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, keyForKeyId)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidBase64InSignatureReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] keyForKeyId = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(keyForKeyId);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return keyForKeyId;
                    }
                    else
                    {
                        return [];
                    }
                };
            });

            using var server = host.GetTestServer();
            var mutatingHttpMessageHandler = new RequestMutatingHandler((request) =>
            {
                ArgumentNullException.ThrowIfNull(request.Headers.Authorization);

                var existingAuthenticationHeaderScheme = request.Headers.Authorization.Scheme;
                var existingAuthenticationHeaderValue = request.Headers.Authorization.Parameter;
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(existingAuthenticationHeaderScheme,
                                                                                                      knownKeyId + ":%InvalidBase64%");
            })
            {
                InnerHandler = server.CreateHandler()
            };

            var sharedKeyHttpMessageHandler = new SharedKeyHttpMessageHandler(knownKeyId, keyForKeyId)
            {
                InnerHandler = mutatingHttpMessageHandler
            };

            using var httpClient = new HttpClient(sharedKeyHttpMessageHandler)
            {
                BaseAddress = server.BaseAddress
            };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task FailureInValidateSharedKeyReturnsUnauthorized()
        {
            const string knownKeyId = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            "keyId",
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Fail("Something went wrong");

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task SuccessInValidateSharedKeyReturnsOkAndAttachesPrincipal()
        {
            const string knownKeyId = "keyId";
            const string KeyIdClaimName = "keyId";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    if (KeyId == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return [];
                    }
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            KeyIdClaimName,
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.NotNull(response.Content);
            Assert.NotNull(response.Content.Headers);
            Assert.NotNull(response.Content.Headers.ContentType);

            Assert.Equal("text/xml", response.Content.Headers.ContentType.MediaType);
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.NotNull(responseBody);

            var responseElement = XElement.Parse(responseBody);

            var actual = responseElement.Elements("claim").Where(claim => claim.Attribute("Type")!.Value == KeyIdClaimName);
            Assert.Single(actual);
            Assert.Equal(knownKeyId, actual.First().Value);
            Assert.Single(responseElement.Elements("claim"));
        }

        [Fact]
        public async Task ExceptionInKeyResolverUnauthorizedAndDivertsThroughAuthenticationFailed()
        {
            const string knownKeyId = "keyId";
            const string KeyIdClaimName = "keyId";
            const string ExceptionMessage = "KeyResolutionException";

            bool authenticationFailedCalled = false;
            Exception? exceptionRaised = null;


            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    throw new Exception(ExceptionMessage);
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        var claims = new[]
                        {
                            new Claim(
                            KeyIdClaimName,
                            context.KeyId,
                            ClaimValueTypes.String,
                            context.Options.ClaimsIssuer)
                        };

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        context.Success();

                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = (context) =>
                    {
                        authenticationFailedCalled = true;
                        exceptionRaised = context.Exception;

                        if (exceptionRaised is not null)
                        {
                            context.Fail(exceptionRaised);
                        }
                        else
                        {
                            context.Fail("Unknown error");
                        }
                        return Task.CompletedTask;

                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.True(authenticationFailedCalled);
            Assert.NotNull(exceptionRaised);
            Assert.Equal(ExceptionMessage, exceptionRaised.Message);
        }

        [Fact]
        public async Task ExceptionInOnValidateSharedKeyReturnsUnauthorizedAndDivertsThroughAuthenticationFailed()
        {
            const string knownKeyId = "keyId";
            const string ExceptionMessage = "ValidateKeyException";

            bool authenticationFailedCalled = false;
            Exception? exceptionRaised = null;


            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (KeyId) =>
                {
                    {
                        if (KeyId == knownKeyId)
                        {
                            return knownKey;
                        }
                        else
                        {
                            return [];
                        }
                    };
                };
                o.Events = new SharedKeyAuthenticationEvents
                {
                    OnValidateSharedKey = (context) =>
                    {
                        throw new Exception(ExceptionMessage);
                    },
                    OnAuthenticationFailed = (context) =>
                    {
                        authenticationFailedCalled = true;
                        exceptionRaised = context.Exception;

                        if (exceptionRaised is not null)
                        {
                            context.Fail(exceptionRaised);
                        }
                        else
                        {
                            context.Fail("Unknown error");
                        }
                        return Task.CompletedTask;

                    }
                };
            });

            using var server = host.GetTestServer();
            var clientHandlerPipeline = new SharedKeyHttpMessageHandler(knownKeyId, knownKey)
            {
                InnerHandler = server.CreateHandler()
            };
            using var httpClient = new HttpClient(clientHandlerPipeline) { BaseAddress = server.BaseAddress };

            var response = await httpClient.GetAsync("https://localhost/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.True(authenticationFailedCalled);
            Assert.NotNull(exceptionRaised);
            Assert.Equal(ExceptionMessage, exceptionRaised.Message);
        }

        private static async Task<IHost> CreateHost(
            Action<SharedKeyAuthenticationOptions> options,
            Uri? baseAddress = null)
        {
            var host = new HostBuilder()
                 .ConfigureWebHost(builder =>
                     builder.UseTestServer()
                        .Configure(app =>
                        {
                            app.UseAuthentication();

                            app.Run(async (context) =>
                            {
                                var request = context.Request;
                                var response = context.Response;

                                var authenticationResult = await context.AuthenticateAsync();

                                if (authenticationResult.Succeeded)
                                {
                                    response.StatusCode = (int)HttpStatusCode.OK;
                                    response.ContentType = "text/xml";

                                    await response.WriteAsync("<claims>");
                                    foreach (Claim claim in context.User.Claims)
                                    {
                                        await response.WriteAsync($"<claim Type=\"{claim.Type}\" Issuer=\"{claim.Issuer}\">{claim.Value}</claim>");
                                    }
                                    await response.WriteAsync("</claims>");
                                }
                                else
                                {
                                    await context.ChallengeAsync();
                                }
                            });
                        })
                .ConfigureServices(services =>
                {
                    AuthenticationBuilder authBuilder;
                    if (options != null)
                    {
                        authBuilder = services.AddAuthentication(SharedKeyAuthenticationDefaults.AuthenticationScheme).AddSharedKey(options);
                    }
                    else
                    {
                        authBuilder = services.AddAuthentication(SharedKeyAuthenticationDefaults.AuthenticationScheme).AddSharedKey();
                    }
                }))
            .Build();

            await host.StartAsync();

            var server = host.GetTestServer();
            if (baseAddress is not null)
            {
                server.BaseAddress = baseAddress;
            }

            return host;
        }

        public class RequestMutatingHandler(Action<HttpRequestMessage> mutate) : DelegatingHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                mutate(request);
                return base.SendAsync(request, cancellationToken);
            }
        }
    }
}
