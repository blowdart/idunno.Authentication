// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Http;
using Microsoft.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace idunno.Authentication.Basic.Test
{
    [ExcludeFromCodeCoverage]
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
        public void SettingAnAsciiRealmWorks()
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
            Exception ex = Assert.Throws<ArgumentException>(() => options.Realm = "💩");
            Assert.Equal("Realm must be US ASCII", ex.Message);
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
            Assert.Single(response.Headers.WwwAuthenticate);
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
            Assert.Single(response.Headers.WwwAuthenticate);
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
                        return Task.CompletedTask;
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
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/", "username", "password");
            Assert.True(called);
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
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateUpgradeRequestedReturnedOnHttpRequest()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
            });
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
            Assert.Equal(StatusCodes.Status421MisdirectedRequest, (int)response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
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
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.True(called);
        }


        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledWhenTheAuthorizationHeaderHasNoCredentials()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsyncWithHeaderValue(server, "https://example.com/", "");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateOnAuthenticationFailedCalledIfExceptionHappensInValidateCredentials()
        {
            const string exceptionMessage = "Something bad happened.";

            bool called = false;
            string actualExceptionMessage = null;

            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        throw new Exception(exceptionMessage);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        called = true;
                        actualExceptionMessage = context.Exception.Message;
                        context.Fail(context.Exception.Message);
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.True(called);
            Assert.Equal(exceptionMessage, actualExceptionMessage);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsIfOnValidateCredentialsDoesNothing()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsIfOnValidateCredentialsFails()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        context.Fail("Failed");
                        return Task.CompletedTask;
                    }
                }
            });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsWhenAnInvalidUTF8AuthenticationHeaderIsSent()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
            });

            var transaction = await SendAsyncWithRawHeaderValue(server, "https://example.com/challenge", "%%%%%");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateSupressionOfWWWAuthenticationHeader()
        {
            var server = CreateServer(new BasicAuthenticationOptions
            {
                SuppressWWWAuthenticateHeader = true
            });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        private static TestServer CreateServer(
            BasicAuthenticationOptions configureOptions,
            Func<HttpContext, Func<Task>, Task> handler = null,
            Uri baseAddress = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    if (handler != null)
                    {
                        app.Use(handler);
                    }

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
                        options.Events = configureOptions.Events;
                        options.Realm = configureOptions.Realm;
                        options.SuppressWWWAuthenticateHeader = configureOptions.SuppressWWWAuthenticateHeader;
                    });
                }
                else
                {
                    services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasic();
                }
            });

            var server = new TestServer(builder)
            {
                BaseAddress = baseAddress
            };

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

        private static async Task<Transaction> SendAsyncWithHeaderValue(TestServer server, string uri, string authorizationHeaderValue, string scheme = "Basic")
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(authorizationHeaderValue.ToCharArray());
            var encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
            request.Headers.Add(HeaderNames.Authorization, scheme+ " " + encodedCredentials);

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

        private static async Task<Transaction> SendAsyncWithRawHeaderValue(TestServer server, string uri, string authorizationHeaderValue, string scheme = "Basic")
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add(HeaderNames.Authorization, scheme + " " + authorizationHeaderValue);

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
