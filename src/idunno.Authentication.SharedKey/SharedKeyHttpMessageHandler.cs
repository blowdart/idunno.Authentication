// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace idunno.Authentication.SharedKey
{
    public class SharedKeyHttpMessageHandler : DelegatingHandler
    {
        public SharedKeyHttpMessageHandler(string keyId, byte[] key)
        {
            KeyId = keyId;
            Key = key;
        }

        public SharedKeyHttpMessageHandler(string keyId, string key) : this(keyId, Convert.FromBase64String(key))
        {
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

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
                    byte[] contentHash = SignatureValidator.CalculateBodyMd5(request).Result;
                    if (contentHash != null)
                    {
                        request.Content.Headers.ContentMD5 = contentHash;
                    }
                }
            }

            byte[] hash = SharedKeySignature.Calculate(request, Key);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                SharedKeyAuthentication.AuthorizationScheme,
                string.Format(CultureInfo.InvariantCulture, "{0}:{1}", KeyId, Convert.ToBase64String(hash)));

            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private string KeyId { get; set; }

        private byte[] Key { get; set; }
    }
}
