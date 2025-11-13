// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Globalization;
using System.Net.Http.Headers;

namespace idunno.Authentication.SharedKey
{
    public class SharedKeyHttpMessageHandler : DelegatingHandler
    {

#pragma warning disable IDE0079
#pragma warning disable IDE0290

        public SharedKeyHttpMessageHandler(string keyId, byte[] key)
        {
            KeyId = keyId;
            Key = key;
        }

        public SharedKeyHttpMessageHandler(string keyId, string key) : this(keyId, Convert.FromBase64String(key))
        {
        }

#pragma warning restore IDE0290
#pragma warning restore IDE0079


        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
#if NET6_0_OR_GREATER            
            ArgumentNullException.ThrowIfNull(request);
#else
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }
#endif

            // Time stamp the request if it's not already timestamped so we can support expiry.
            if (request.Headers.Date == null)
            {
                request.Headers.Date = DateTime.UtcNow;
            }

            // Check if we have request content, if we do then we need to add a Content-MD5 header if it doesn't already exist.
            // However we can't do this if we're chunked.
            if (request.Headers.TransferEncodingChunked == null || !(bool)request.Headers.TransferEncodingChunked)
            {
                // We can't rely on the length header, as it's not set yet.
                if (request.Content != null && request.Content.Headers.ContentMD5 == null)
                {
                    byte[] contentHash = await SignatureValidator.CalculateBodyMd5(request).ConfigureAwait(true);
                    if (contentHash != null && contentHash.Length != 0)
                    {
                        request.Content.Headers.ContentMD5 = contentHash;
                    }
                }
            }

            byte[] hash = SharedKeySignature.Calculate(request, Key);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                SharedKeyAuthentication.AuthorizationScheme,
                string.Format(CultureInfo.InvariantCulture, "{0}:{1}", KeyId, Convert.ToBase64String(hash)));

            return await base.SendAsync(request, cancellationToken).ConfigureAwait(true);
        }

        private string KeyId { get; set; }

        private byte[] Key { get; set; }
    }
}
