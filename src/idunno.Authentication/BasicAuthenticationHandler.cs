// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace idunno.Authentication
{
    internal class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private const string _Scheme = "Basic";

        public BasicAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new BasicAuthenticationEvents Events
        {
            get { return (BasicAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.IsHttps)
            {
                return AuthenticateResult.NoResult();
            }

            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith(_Scheme + ' ', StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

            string encodedCredentials = authorizationHeader.Substring(_Scheme.Length).Trim();

            if (string.IsNullOrEmpty(encodedCredentials))
            {
                const string noCredentialsMessage = "No credentials";
                Logger.LogInformation(noCredentialsMessage);
                return AuthenticateResult.Fail(noCredentialsMessage);
            }

            try
            {
                string decodedCredentials = string.Empty;
                try
                {
                    decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to decode credentials : {encodedCredentials}", ex);
                }

                var delimiterIndex = decodedCredentials.IndexOf(':');
                if (delimiterIndex == -1)
                {
                    const string missingDelimiterMessage = "Invalid credentials, missing delimiter.";
                    Logger.LogInformation(missingDelimiterMessage);
                    return AuthenticateResult.Fail(missingDelimiterMessage);
                }

                var username = decodedCredentials.Substring(0, delimiterIndex);
                var password = decodedCredentials.Substring(delimiterIndex + 1);

                var validateCredentialsContext = new ValidateCredentialsContext(Context, Scheme, Options)
                {
                    Username = username,
                    Password = password
                };

                await Options.Events.ValidateCredentials(validateCredentialsContext);

                if (validateCredentialsContext.Result != null)
                {
                    var ticket = new AuthenticationTicket(validateCredentialsContext.Principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.NoResult();
            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Options.Events.AuthenticationFailed(authenticationFailedContext);

                if (authenticationFailedContext.Result.Succeeded)
                {
                    return AuthenticateResult.Success(authenticationFailedContext.Result.Ticket);
                }

                if (authenticationFailedContext.Result.None)
                {
                    return AuthenticateResult.NoResult();
                }

                throw;
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;

            var headerValue = _Scheme + $" realm=\"{Options.Realm}\"";
            Response.Headers.Append(HeaderNames.WWWAuthenticate, headerValue);

            return Task.CompletedTask;
        }
    }
}