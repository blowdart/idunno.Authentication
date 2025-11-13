// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace idunno.Authentication.SharedKey
{
    internal class SharedKeyAuthenticationHandler : AuthenticationHandler<SharedKeyAuthenticationOptions>
    {
#if NET8_0_OR_GREATER
        public SharedKeyAuthenticationHandler(
            IOptionsMonitor<SharedKeyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder) : base(options, logger, encoder)
        {
        }

        [Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
#endif

#pragma warning disable IDE0290
        public SharedKeyAuthenticationHandler(
            IOptionsMonitor<SharedKeyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }
#pragma warning restore IDE0290

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new SharedKeyAuthenticationEvents? Events
        {
            get { return (SharedKeyAuthenticationEvents?)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new SharedKeyAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
#if NET6_0_OR_GREATER
            string? authorizationHeader = Request.Headers.Authorization;
#else
            string? authorizationHeader = Request.Headers["Authorization"];
#endif

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            // Exact match on purpose, rather than using string compare
            // asp.net request parsing will always trim the header and remove trailing spaces
            if (SharedKeyAuthentication.AuthorizationScheme == authorizationHeader)
            {
                const string noCredentialsMessage = "SharedKey scheme found but the header had no credentials.";
                Logger.LogInformation(noCredentialsMessage);
                return AuthenticateResult.Fail(noCredentialsMessage);
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

            var credentials = authorizationHeader[SharedKeyAuthentication.AuthorizationScheme.Length..].Trim();

            string keyId;
            if (credentials.Contains(':', StringComparison.OrdinalIgnoreCase))
            {
                keyId = credentials[..credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase)];
            }
            else
            {
                const string invalidFormat = "Invalid key:signature format.";
                Logger.LogInformation(invalidFormat);
                return AuthenticateResult.Fail(invalidFormat);
            }

            try
            {
                byte[]? key = Options.KeyResolver(keyId);
                if (key == null || key.Length == 0)
                {
                    const string noKey = "Key identifier could not be resolved to a key.";
                    Logger.LogInformation(noKey);
                    return AuthenticateResult.Fail(noKey);
                }

                string encodedSignature = credentials[(credentials.IndexOf(':', StringComparison.OrdinalIgnoreCase) + 1)..];
                if (encodedSignature == null || encodedSignature.Length == 0)
                {
                    const string missingSignature = "Key identifier found but no signature was supplied.";
                    Logger.LogInformation(missingSignature);
                    return AuthenticateResult.Fail(missingSignature);
                }

                byte[] providedSignature;
                try
                {
                    providedSignature = Convert.FromBase64String(encodedSignature);
                }
                catch (Exception ex)
                {
                    const string failedToDecodeSignature = "Cannot build signature from decoded base64 value";
                    Logger.LogInformation(message: failedToDecodeSignature, exception: ex);
                    return AuthenticateResult.Fail(ex);
                }

                // Check that when have request content we also have an matching MD5 header.
                if (Request.Headers.ContentLength != null && Request.Headers.ContentLength != 0)
                {
                    // However we can't do this if we're chunked.
                    if (!Request.Headers[HeaderNames.TransferEncoding].ToString().Contains("chunked", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Request.Headers[HeaderNames.ContentMD5].Count == 0 ||
                            string.IsNullOrEmpty(Request.Headers[HeaderNames.ContentMD5].ToString()) ||
                            Request.Headers[HeaderNames.ContentMD5].ToString().Trim().Length == 0)
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

#if NET5_0_OR_GREATER
                        var calculatedContentHash = MD5.HashData(new UTF8Encoding(false).GetBytes(body));
#else
                        using var md5 = MD5.Create();
                        var calculatedContentHash = md5.ComputeHash(new UTF8Encoding(false).GetBytes(body));
#endif

                        byte[] providedContentHash;
                        try
                        {
                            // Null check enforced by the outer if statement.
                            providedContentHash = Convert.FromBase64String(Request.Headers[HeaderNames.ContentMD5]!);
                        }
                        catch (Exception ex)
                        {
                            const string failedToDecodeSignature = "Cannot decode Content-MD5 header.";
                            Logger.LogInformation(message: failedToDecodeSignature, exception: ex);
                            return AuthenticateResult.Fail(ex);
                        }

                        if (!CryptographicOperations.FixedTimeEquals(calculatedContentHash, providedContentHash))
                        {
                            const string contentHashCheckFailed = "MD5 checksum failed to match content.";
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

                if (Events != null)
                {
                    await Events.ValidateSharedKey(validateSharedKeyContext).ConfigureAwait(true);
                }

                if (validateSharedKeyContext.Result != null &&
                    validateSharedKeyContext.Result.Succeeded)
                {
                    var ticket = new AuthenticationTicket(validateSharedKeyContext.Principal!, Scheme.Name);
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

                if (Events != null)
                {
                    await Events.AuthenticationFailed(authenticationFailedContext).ConfigureAwait(true);
                }

                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }
    }
}
