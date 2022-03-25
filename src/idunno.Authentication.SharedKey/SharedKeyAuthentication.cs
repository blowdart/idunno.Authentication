// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace idunno.Authentication.SharedKey
{
    internal static class SharedKeyAuthentication
    {
        /// <summary>
        /// The name of the authentication type.
        /// </summary>
        public static string AuthorizationScheme
        {
            get
            {
                return "SharedKey";
            }
        }

        /// <summary>
        /// Tries to parse an authentication header value into an key identifier and HMAC.
        /// </summary>
        /// <param name="authenticationHeaderValue">The authentication header value.</param>
        /// <param name="keyId">The key identifier.</param>
        /// <param name="hmac">The HMAC.</param>
        /// <returns>True if parsing was successful, otherwise false.</returns>
        internal static bool TryParse(string authenticationHeaderValue, out string keyId, out string hmac)
        {
            if (authenticationHeaderValue.IndexOf(":", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var colonPosition = authenticationHeaderValue.IndexOf(":", StringComparison.OrdinalIgnoreCase);
                if (colonPosition != 0 && colonPosition != authenticationHeaderValue.Length)
                {
                    keyId = authenticationHeaderValue[..colonPosition];
                    hmac = authenticationHeaderValue[(colonPosition + 1)..];
                    return true;
                }
            }

            keyId = null;
            hmac = null;
            return false;
        }

        /// <summary>
        /// Tries to parse an authentication header value into an account name and HMAC.
        /// </summary>
        /// <param name="authenticationHeaderValue">The authentication header value.</param>
        /// <param name="keyId">The key identifier.</param>
        /// <param name="hmac">The HMAC.</param>
        /// <returns>True if parsing was successful, otherwise false.</returns>
        internal static bool TryParse(string authenticationHeaderValue, out string keyId, out byte[] hmac)
        {
            bool result = TryParse(authenticationHeaderValue, out keyId, out string hmacAsString);

            hmac = result ? Convert.FromBase64String(hmacAsString) : null;

            return result;
        }
    }
}
