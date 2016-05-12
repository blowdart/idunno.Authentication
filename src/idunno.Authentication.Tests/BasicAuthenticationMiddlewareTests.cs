// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using Microsoft.Net.Http.Headers;

using Xunit;

namespace idunno.Authentication.Tests
{
    public class BasicAuthenticationMiddlewareTests
    {
        [Fact]
        public void SettingANonAsciiRealmThrows()
        {
            var options = new BasicAuthenticationOptions();
            Exception ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Realm = "💩");
            Assert.Equal(ex.Message, "Realm must be US ASCII\r\nParameter name: Realm");
        }

        [Fact]
        public async Task NormalRequestPassesThrough()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("http://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NormalWithAuthRequestPassesThrough()
        {
            var server = CreateServer(new BasicAuthenticationOptions());

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");       
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenicateHeaderAndScheme()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("http://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenicateHeaderAndSchemeWithSpecifiedRealm()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Realm = "realm"
            });
            var response = await server.CreateClient().GetAsync("http://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ForbiddenPathReturnsForbiddenStatus()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("http://example.com/forbidden");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWithWWWAuthenicateHeaderAndSchemeWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
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
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ChallengePathReturnsForbiddenWhenAnAuthorizeHeaderIsSentAndPassesValidation()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        var claims = new[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, context.Username)
                        };

                        context.Ticket = new AuthenticationTicket(
                            new ClaimsPrincipal(new ClaimsIdentity(claims, context.Options.AuthenticationScheme)),
                            new AuthenticationProperties(), context.Options.AuthenticationScheme);

                        context.HandleResponse();

                        return Task.FromResult<object>(null);
                    }
                }
            });

            var transaction = await SendAsync(server, "http://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Forbidden, transaction.Response.StatusCode);
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

            var transaction = await SendAsync(server, "http://example.com/challenge", "username", "password");
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

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.Equal(true, called);
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

            var transaction = await SendAsync(server, "http://example.com/");
            Assert.Equal(false, called);
        }

        private static TestServer CreateServer(
            BasicAuthenticationOptions configureOptions, 
            Func<HttpContext, bool> handler = null,
            Uri baseAddress = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
            {
                if (configureOptions != null)
                {
                    app.UseBasicAuthentication(configureOptions);
                }

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
                        await context.Authentication.ForbidAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                    }
                    else if (request.Path == new PathString("/challenge"))
                    {
                        await context.Authentication.ChallengeAsync(BasicAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties());
                    }
                    else
                    {
                        await next();
                    }
                });
            })
            .ConfigureServices(services => services.AddAuthentication());

            var server = new TestServer(builder);
            server.BaseAddress = baseAddress;
            return server;
        }

        private static async Task<Transaction> SendAsync(TestServer server, string uri, string userName = null, string password = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(userName))
            {
                string credentials = $"{userName}:{password}";
                byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(credentials.ToCharArray());
                var encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
                request.Headers.Add(HeaderNames.Authorization, $"Basic {encodedCredentials}");
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
