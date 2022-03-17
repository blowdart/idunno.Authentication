// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
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
            httpClient.DefaultRequestHeaders.Add(AuthenticationHeaderName, (string)null);
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
            const string knownKeyId = "keyid";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (keyID) =>
                {
                    if (keyID == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return Array.Empty<byte>();
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
            const string knownKeyId = "keyid";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (keyID) =>
                {
                    if (keyID == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return new byte[] {0xDE, 0xAD, 0xBE, 0xEF};
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
        public async Task AuthorizedRequestWithKnownKeyIdButNoSeperatorReturnsUnauthorized()
        {
            const string knownKeyId = "keyid";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (keyID) =>
                {
                    if (keyID == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return Array.Empty<byte>();
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
        public async Task AuthorizedRequestWithKnownKeyIdAndMatchingKeyReturnsOk()
        {
            const string knownKeyId = "keyid";
            byte[] knownKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(knownKey);

            using var host = await CreateHost(o => {
                o.KeyResolver = (keyID) =>
                {
                    if (keyID == knownKeyId)
                    {
                        return knownKey;
                    }
                    else
                    {
                        return Array.Empty<byte>();
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

        private static async Task<IHost> CreateHost(
            Action<SharedKeyAuthenticationOptions> options,
            Func<HttpContext, bool> handler = null,
            Uri baseAddress = null)
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
            server.BaseAddress = baseAddress;
            return host;

        }
    }
}
