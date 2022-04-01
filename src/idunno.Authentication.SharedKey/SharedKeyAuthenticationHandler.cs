// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

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

            // Check request age
            if (Request.Headers[HeaderNames.Date].Count == 0)
            {
                const string noDate = "Request has no date header.";
                Logger.LogInformation(noDate);
                return AuthenticateResult.Fail(noDate);
            }

            if (!DateTime.TryParse(Request.Headers[HeaderNames.Date].ToString(), out DateTime dateHeader))
            {
                const string invalidDate = "Date header is invalid.";
                Logger.LogInformation(invalidDate);
                return AuthenticateResult.Fail(invalidDate);
            }

            var currentDateTime = DateTime.UtcNow;
            var requestDateTime = dateHeader.ToUniversalTime();
            var minimumAcceptableRequestDate = currentDateTime.Subtract(Options.MaximumMessageValidity);
            var maximumAcceptableRequestDate = currentDateTime.Add(Options.MaximumMessageValidity);

            if (currentDateTime.Subtract(Options.MaximumMessageValidity) > requestDateTime ||
                currentDateTime.Add(Options.MaximumMessageValidity) < requestDateTime)
            {
                const string requestOutsideValidityRange = "Request is outside of validity range.";
                Logger.LogInformation(requestOutsideValidityRange);
                return AuthenticateResult.Fail(requestOutsideValidityRange);
            }

            // Parse and validate the authorization header
            var credentials = authorizationHeader[SharedKeyAuthentication.AuthorizationScheme.Length..].Trim();
            if (string.IsNullOrEmpty(credentials))
            {
                const string noCredentials = "No credentials specified";
                Logger.LogInformation(noCredentials);
                return AuthenticateResult.Fail(noCredentials);
            }

            string keyId;
            if (credentials.Contains(':', StringComparison.OrdinalIgnoreCase))
            {
                keyId = credentials[..credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase)];
            }
            else
            {
                const string noKeyId = "No key identifier specified.";
                Logger.LogInformation(noKeyId);
                return AuthenticateResult.Fail(noKeyId);
            }

            byte[] key = Options.KeyResolver(keyId);
            if (key == null || key.Length == 0)
            {
                const string noKey = "Key identifier could not be resolved to a key.";
                Logger.LogInformation(noKey);
                return AuthenticateResult.Fail(noKey);
            }

            try
            {
                string encodedSignature = credentials[(credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase) + 1)..];
                byte[] providedSignature;
                try
                {
                    providedSignature = Convert.FromBase64String(encodedSignature);
                }
                catch (Exception ex)
                {
                    const string failedToDecodeSignature = "Cannot build signature from decoded base64 value, exception {ex} encountered.";
                    Logger.LogInformation(failedToDecodeSignature, ex);
                    return AuthenticateResult.Fail(ex);
                }

                // Check that when have request content we also have an matching MD5 header.
                if (Request.Headers.ContentLength != null && Request.Headers.ContentLength != 0)
                {
                    // However we can't do this if we're chunked.
                    if (!Request.Headers[HeaderNames.TransferEncoding].ToString().Contains("chunked", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Request.Headers[HeaderNames.ContentMD5].Count == 0 || Request.Headers[HeaderNames.ContentMD5].ToString().Trim().Length == 0)
                        {
                            const string bodyButNoMD5Header = "Request has content but no md5 header.";
                            Logger.LogInformation(bodyButNoMD5Header);
                            return AuthenticateResult.Fail(bodyButNoMD5Header);
                        }

                        // We first need to enable buffering so we can pull the body content out, then reset the stream position so anything after us
                        // can still read the body.
                        Request.EnableBuffering();
                        string body;
                        var currentPosition = Request.Body.Position;
                        using (var reader = new StreamReader(Request.Body, leaveOpen: true))
                        {
                            Request.Body.Position = 0;
                            body = await reader.ReadToEndAsync().ConfigureAwait(true);
                        }
                        Request.Body.Position = currentPosition;

                        using var md5 = MD5.Create();
                        var calculatedContentHash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(body));

                        byte[] providedContentHash;
                        try
                        {
                            providedContentHash = Convert.FromBase64String(Request.Headers[HeaderNames.ContentMD5]);
                        }
                        catch (Exception ex)
                        {
                            const string failedToDecodeSignature = "Cannot decode Content-MD5 header, exception {ex} encountered.";
                            Logger.LogInformation(failedToDecodeSignature, ex);
                            return AuthenticateResult.Fail(ex);
                        }

                        if (!CryptographicOperations.FixedTimeEquals(calculatedContentHash, providedContentHash))
                        {
                            const string contentHashCheckFailed = "Content has does not match content hash";
                            Logger.LogInformation(contentHashCheckFailed);
                            return AuthenticateResult.Fail(contentHashCheckFailed);
                        }
                    }
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
