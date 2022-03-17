// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace idunno.Authentication.SharedKey
{
    internal class SharedKeyAuthenticationHandler : AuthenticationHandler<SharedKeyAuthenticationOptions>
    {

        public SharedKeyAuthenticationHandler(
            IOptionsMonitor<SharedKeyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new SharedKeyAuthenticationEvents Events
        {
            get { return (SharedKeyAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new SharedKeyAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith(SharedKeyAuthentication.AuthorizationScheme+ ' ', StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

            var credentials = authorizationHeader.Substring(SharedKeyAuthentication.AuthorizationScheme.Length).Trim();
            if (string.IsNullOrEmpty(credentials))
            {
                const string noCredentials = "No credentials specified";
                Logger.LogInformation(noCredentials);
                return AuthenticateResult.Fail(noCredentials);
            }

            string keyId;
            if (credentials.Contains(":", StringComparison.OrdinalIgnoreCase))
            {
                keyId = credentials.Substring(0, credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                const string noKeyId = "No key identifier specified.";
                Logger.LogInformation(noKeyId);
                return AuthenticateResult.Fail(noKeyId);
            }

            byte[] key = Options.KeyResolver(credentials);
            if (key == null || key.Length == 0)
            {
                const string noKey = "Key identifier could not be resolved to a key.";
                Logger.LogInformation(noKey);
                return AuthenticateResult.Fail(noKey);
            }

            try
            {
                string encodedSignature = credentials.Substring(credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase) + 1);
                byte[] providedSignature;
                try
                {
                    providedSignature = Convert.FromBase64String(encodedSignature);
                }
                catch (Exception ex)
                {
                    const string failedToDecodeSignature = "Cannot build signature from decoded base64 value, exception {0} encountered.";
                    var logMessage = string.Format(CultureInfo.InvariantCulture, failedToDecodeSignature, ex.Message);
                    Logger.LogInformation(logMessage);
                    return AuthenticateResult.Fail(logMessage);
                }

                byte[] calculatedSignature = SharedKeySignature.Calculate(Request, key);
                if (!CryptographicOperations.FixedTimeEquals(calculatedSignature, providedSignature))
                {
                    const string invalidSignature = "Invalid Signature.";
                    Logger.LogInformation(invalidSignature);
                    return AuthenticateResult.Fail(invalidSignature);
                }

                var validateSharedKeyContext = new ValidateSharedKeyContext(Context, Scheme, Options)
                {
                    KeyId = keyId
                };

                await Events.ValidateSharedKey(validateSharedKeyContext).ConfigureAwait(true);

                if (validateSharedKeyContext.Result != null &&
                    validateSharedKeyContext.Result.Succeeded)
                {
                    var ticket = new AuthenticationTicket(validateSharedKeyContext.Principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                if (validateSharedKeyContext.Result != null &&
                    validateSharedKeyContext.Result.Failure != null)
                {
                    return AuthenticateResult.Fail(validateSharedKeyContext.Result.Failure);
                }

                return AuthenticateResult.NoResult();

            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new SharedKeyAuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext).ConfigureAwait(true);

                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }
    }
}
