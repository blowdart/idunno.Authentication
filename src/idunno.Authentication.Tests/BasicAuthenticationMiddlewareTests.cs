// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using Microsoft.Net.Http.Headers;

using Xunit;

namespace idunno.Authentication.Tests
{
    public class BasicAuthenticationHandlerTests
    {
        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddBasic();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(BasicAuthenticationDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("BasicAuthenticationHandler", scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public void SettingAnAsciiRealWorks()
        {
            const string realm = "Realm";
            var options = new BasicAuthenticationOptions
            {
                Realm = realm
            };
            Assert.Equal(realm, options.Realm);
        }

        [Fact]
        public void SettingANonAsciiRealmThrows()
        {
            var options = new BasicAuthenticationOptions();
            Exception ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Realm = "💩");
            Assert.Equal("Realm must be US ASCII\r\nParameter name: Realm", ex.Message);
        }

        [Fact]
        public async Task NormalRequestPassesThrough()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NormalWithAuthRequestPassesThrough()
        {
            var server = CreateServer(new BasicAuthenticationOptions());

            var transaction = await SendAsync(server, "https://example.com/", "username", "password");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }


        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenicateHeaderAndScheme()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ProtectedPathRequestWithBadSchemeReturnsUnauthorized()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var transaction = await SendAsync(server, "https://example.com/unauthorized", "username", "password", "bogus");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ForbiddenPathReturnsForbiddenStatus()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/forbidden");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWithWWWAuthenicateHeaderAndSchemeWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWithWWWAuthenicateHeaderSchemeAndConfiguredRealmWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Realm = "realm"
            });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizeWhenAnAuthorizeHeaderIsSentAndFailsValidation()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {

                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsCalledWhenCredentialsProvided()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/", "username", "password");
            Assert.True(called);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledOverHttp()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledWhenNoCredentialsAreProvided()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateHandlerWillThrowExceptionByDefaultOnHttpWhenChallengeIsStarted()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                AllowInsecureProtocol = false
            });

            var transaction = await SendAsync(server, "http://example.com/challenge");
            Assert.Equal(HttpStatusCode.InternalServerError, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateHandlerWillRespondOnHttpWhenSecurityIsDisabled()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
            {
                AllowInsecureProtocol = true,
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.True(called);
        }

        private static TestServer CreateServer(
            BasicAuthenticationOptions configureOptions,
            Func<HttpContext, bool> handler = null,
            Uri baseAddress = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use(async (context, next) =>
                    {
                        var request = context.Request;
                        var response = context.Response;

                        if (request.Path == new PathString("/"))
                        {
                            response.StatusCode = (int)HttpStatusCode.OK;
                        }
                        else if (request.Path == new PathString("/unauthorized"))
                        {
                            response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        }
                        else if (request.Path == new PathString("/forbidden"))
                        {
                            await context.ForbidAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                        }
                        else if (request.Path == new PathString("/challenge"))
                        {
                            await context.ChallengeAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
            .ConfigureServices(services =>
            {
                if (configureOptions != null)
                {
                    services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasic(options =>
                    {
                        options.Realm = configureOptions.Realm;
                        options.Events = configureOptions.Events;
                    });
                }
                else
                {
                    services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasic();
                }
            });

            var server = new TestServer(builder);
            server.BaseAddress = baseAddress;

            return server;
        }

        private static async Task<Transaction> SendAsync(TestServer server, string uri, string userName = null, string password = null, string scheme = "Basic")
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(userName))
            {
                string credentials = $"{userName}:{password}";
                byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(credentials.ToCharArray());
                var encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
                request.Headers.Add(HeaderNames.Authorization, $"{scheme} {encodedCredentials}");
            }
            var transaction = new Transaction
            {
                Request = request,
                Response = await server.CreateClient().SendAsync(request),
            };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content != null &&
                transaction.Response.Content.Headers.ContentType != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }
            return transaction;
        }

        private class Transaction
        {
            public HttpRequestMessage Request { get; set; }
            public HttpResponseMessage Response { get; set; }
            public string ResponseText { get; set; }
            public XElement ResponseElement { get; set; }
        }
    }
}
