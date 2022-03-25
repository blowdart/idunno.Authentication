// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace idunno.Authentication.SharedKey
{
    internal class SignatureValidator
    {
        /// <summary>
        /// Calculates the MD5 checksum of a <paramref name="request"/> body.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> for which to calculate a checksum.</param>
        /// <returns>The hash value for the <paramref name="request"/> body.</returns>
        public static async Task<byte[]> CalculateBodyMd5(HttpRequestMessage request)
        {
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
            using var bodyStream = new MemoryStream();
            await request.Content.CopyToAsync(bodyStream).ConfigureAwait(false);
            bodyStream.Position = 0;
            if (bodyStream.Length <= 0)
            {
                return null;
            }

            using var md5 = MD5.Create();
            return md5.ComputeHash(bodyStream);
        }
    }
}
