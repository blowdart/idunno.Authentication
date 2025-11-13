// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETSTANDARD2_0
#nullable enable
#endif

using System.Text.Encodings.Web;
using System.Text;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace idunno.Authentication.Basic
{
    internal class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private const string _Scheme = "Basic";

        private readonly UTF8Encoding _utf8ValidatingEncoding = new (false, true);

        private readonly Encoding _iso88591ValidatingEncoding = Encoding.GetEncoding("ISO-8859-1",new EncoderExceptionFallback(), new DecoderExceptionFallback());

#if NET8_0_OR_GREATER
        public BasicAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder) : base(options, logger, encoder)
        {
        }

        [Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
#endif
#pragma warning disable IDE0290
        public BasicAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
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
        protected new BasicAuthenticationEvents? Events
        {
            get { return (BasicAuthenticationEvents?)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
#if NET6_0_OR_GREATER
            string? authorizationHeader = Request.Headers.Authorization;
#else
            string? authorizationHeader = Request.Headers["Authorization"];
#endif

            if (authorizationHeader is null)
            {
               return AuthenticateResult.NoResult();
            }

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            // Exact match on purpose, rather than using string compare
            // asp.net request parsing will always trim the header and remove trailing spaces
            if (_Scheme == authorizationHeader)
            {
                const string noCredentialsMessage = "Authorization scheme was Basic but the header had no credentials.";
                Logger.LogInformation(noCredentialsMessage);
                return AuthenticateResult.Fail(noCredentialsMessage);
            }

            if (!authorizationHeader.StartsWith(_Scheme + ' ', StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

#if NET6_0_OR_GREATER
            string encodedCredentials = authorizationHeader[_Scheme.Length..].Trim();
#else
            string encodedCredentials = authorizationHeader.Substring(_Scheme.Length).Trim();
#endif

            try
            {
                string decodedCredentials = string.Empty;
                byte[] base64DecodedCredentials;
                try
                {
                    base64DecodedCredentials = Convert.FromBase64String(encodedCredentials);
                }
                catch (FormatException)
                {
                    const string failedToDecodeCredentials = "Cannot convert credentials from Base64.";
                    Logger.LogInformation(failedToDecodeCredentials);
                    return AuthenticateResult.Fail(failedToDecodeCredentials);
                }

                try
                {
                    if (Options.EncodingPreference == EncodingPreference.Utf8)
                    {
                        decodedCredentials = _utf8ValidatingEncoding.GetString(base64DecodedCredentials);
                    }
                    else if (Options.EncodingPreference == EncodingPreference.Latin1)
                    {
                        decodedCredentials = _iso88591ValidatingEncoding.GetString(base64DecodedCredentials);
                    }
                    else if (Options.EncodingPreference == EncodingPreference.PreferUtf8)
                    {
                        try
                        {
                            decodedCredentials = _utf8ValidatingEncoding.GetString(base64DecodedCredentials);
                        }
                        catch
                        {
                            decodedCredentials = _iso88591ValidatingEncoding.GetString(base64DecodedCredentials);
                        }
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException(nameof(Options), "Unknown EncodingPreference");
                    }
                }
                catch (Exception ex)
                {
                    const string failedToDecodeCredentials = "Cannot build credentials from decoded base64 value.";
                    Logger.LogInformation(message: failedToDecodeCredentials, exception: ex);
                    return AuthenticateResult.Fail(ex.Message);
                }

                var delimiterIndex = decodedCredentials.IndexOf(":", StringComparison.OrdinalIgnoreCase);
                if (delimiterIndex == -1)
                {
                    const string missingDelimiterMessage = "Invalid credentials, missing delimiter.";
                    Logger.LogInformation(message: missingDelimiterMessage);
                    return AuthenticateResult.Fail(missingDelimiterMessage);
                }

#if NET6_0_OR_GREATER
                var username = decodedCredentials[..delimiterIndex];
                var password = decodedCredentials[(delimiterIndex + 1)..];

#else
                var username = decodedCredentials.Substring(0, delimiterIndex);
                var password = decodedCredentials.Substring(delimiterIndex + 1);
#endif

                var validateCredentialsContext = new ValidateCredentialsContext(
                    username,
                    password,
                    Context,
                    Scheme,
                    Options);

                if (Events is not null)
                {
                    await Events.ValidateCredentials(validateCredentialsContext);
                }

                if (validateCredentialsContext.Result != null &&
                    validateCredentialsContext.Principal != null &&
                    validateCredentialsContext.Result.Succeeded)
                {
                    var ticket = new AuthenticationTicket(validateCredentialsContext.Principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                if (validateCredentialsContext.Result != null &&
                    validateCredentialsContext.Result.Failure != null)
                {
                    return AuthenticateResult.Fail(validateCredentialsContext.Result.Failure);
                }

                return AuthenticateResult.NoResult();
            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new BasicAuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                if (Events is not null)
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

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (!Request.IsHttps && !Options.AllowInsecureProtocol)
            {
                const string insecureProtocolMessage = "Request is HTTP, Basic Authentication will not respond.";
                Logger.LogInformation(insecureProtocolMessage);
                // 421 Misdirected Request
                // The request was directed at a server that is not able to produce a response.
                // This can be sent by a server that is not configured to produce responses for the combination of scheme and authority that are included in the request URI.
                Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
            }
            else
            {
                Response.StatusCode = 401;
                if (!Options.SuppressWWWAuthenticateHeader)
                {
                    var headerValue = _Scheme + $" realm=\"{Options.Realm}\"";
                    if (Options.AdvertiseEncodingPreference)
                    {
                        switch (Options.EncodingPreference)
                        {
                            case EncodingPreference.Utf8:
                            case EncodingPreference.PreferUtf8:
                                headerValue+= ", charset=\"UTF-8\"";
                                break;
                            case EncodingPreference.Latin1:
                                headerValue += ", charset=\"ISO-8859-1\"";
                                break;
                            default:
                                break;

                        }
                    }
                    Response.Headers.Append(HeaderNames.WWWAuthenticate, headerValue);
                }
            }

            return Task.CompletedTask;
        }
    }
}
