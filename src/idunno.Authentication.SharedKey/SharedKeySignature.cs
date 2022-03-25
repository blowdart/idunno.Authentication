// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.SharedKey
{
    internal static class SharedKeySignature
    {
        /// <summary>
        /// Calculates a SHA256 HMAC for the <seealso cref="request"/>.
        /// </summary>
        /// <param name="request">The request to calculate a hash for.</param>
        /// <param name="key">The shared key used to sign the request.</param>
        /// <returns>A SHA256 HMAC of the canonicalized request.</returns>
        internal static byte[] Calculate(HttpRequestMessage request, byte[] key)
        {
            var canonicalizedRequest = request.CanonicalizeHeaders() + request.CanonicalizeResource();
            return CalculateHmac256(key, canonicalizedRequest);
        }

        /// <summary>
        /// Calculates a SHA256 HMAC for the <seealso cref="request"/>.
        /// </summary>
        /// <param name="request">The request to calculate a hash for.</param>
        /// <param name="key">The shared key used to sign the request.</param>
        /// <returns>A SHA256 HMAC of the canonicalized request.</returns>
        internal static byte[] Calculate(HttpRequest request, byte[] key)
        {
            var canonicalizedRequest = request.CanonicalizeHeaders() + request.CanonicalizeResource();
            return CalculateHmac256(key, canonicalizedRequest);
        }

        /// <summary>
        /// Calculates a SHA256 HMAC for the plain text, using the specified key.
        /// </summary>
        /// <param name="key">The key to use in the HMAC.</param>
        /// <param name="plainText">The plain text to calculate the HMAC over.</param>
        /// <returns>A SHA256 HMAC</returns>
        private static byte[] CalculateHmac256(byte[] key, string plainText)
        {
            using HashAlgorithm hashAlgorithm = new HMACSHA256(key);
            byte[] messageBuffer = Encoding.UTF8.GetBytes(plainText);
            return hashAlgorithm.ComputeHash(messageBuffer);
        }
    }
}
