// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;

using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.SharedKey
{
    internal static class CanonicalizationHelpers
    {
        // TODO: Date Override Header

        public static string CanonicalizeHeaders(this HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var headerPortion = new CanonicalizedStringBuilder();
            headerPortion.Append(request.Method.ToString().ToUpperInvariant());
            if (request.Content.Headers == null)
            {
                headerPortion.Append(string.Empty); // Encoding
                headerPortion.Append(string.Empty); // Language
                headerPortion.Append(0);            // Length
                headerPortion.Append(string.Empty); // MD5
                headerPortion.Append(string.Empty); // Content-Type
            }
            else
            {
                headerPortion.Append(request.Content.Headers.ContentEncoding);
                headerPortion.Append(request.Content.Headers.ContentLanguage);
                headerPortion.Append(request.Content.Headers == null ? "0" : ((long)request.Content.Headers.ContentLength).ToString(CultureInfo.InvariantCulture)) ;
                headerPortion.Append(request.Content.Headers.ContentMD5 == null ? string.Empty : Convert.ToBase64String(request.Content.Headers.ContentMD5));
                headerPortion.Append(request.Content.Headers.ContentType);
            }
            headerPortion.Append(request.Headers.Date.HasValue ? request.Headers.Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            headerPortion.Append(request.Headers.IfModifiedSince);
            headerPortion.Append(request.Headers.IfMatch);
            headerPortion.Append(request.Headers.IfNoneMatch);
            headerPortion.Append(request.Headers.IfUnmodifiedSince);
            headerPortion.Append(request.Headers.Range);
            return headerPortion.ToString();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "The azure specification normalizes on lower case.")]
        public static string CanonicalizeResource(this HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var canonicalizedResource = new StringBuilder();

            canonicalizedResource.Append("/");
            canonicalizedResource.Append(request.Headers.Host.ToLowerInvariant()); // We are using the host name rather than an account owner because that is too azure specific.
            canonicalizedResource.Append(WebUtility.UrlEncode(request.RequestUri.AbsolutePath));

            if (request.RequestUri.Query.Length > 0 )
            {
                // We have query parameters
                NameValueCollection queryNameValueCollection = HttpUtility.ParseQueryString(request.RequestUri.Query);

                var orderedQueryStringParameters = from q in queryNameValueCollection.AllKeys.Distinct() orderby q select q;

                foreach (string parameterName in queryNameValueCollection.Keys)
                {
                    canonicalizedResource.Append("\n");
                    canonicalizedResource.Append(parameterName);
                    canonicalizedResource.Append(":");
                    canonicalizedResource.Append(queryNameValueCollection[parameterName]);
                }
            }

            return canonicalizedResource.ToString();
        }

        public static string CanonicalizeHeaders(this HttpRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var headerPortion = new CanonicalizedStringBuilder();
            headerPortion.Append(request.Method.ToString().ToUpperInvariant());
            if (request.Headers == null)
            {
                headerPortion.Append(string.Empty); // Encoding
                headerPortion.Append(string.Empty); // Language
                headerPortion.Append(0);            // Length
                headerPortion.Append(string.Empty); // MD5
                headerPortion.Append(string.Empty); // Content-Type
            }
            else
            {
                headerPortion.Append(request.GetTypedHeaders().AcceptEncoding);
                headerPortion.Append(request.GetTypedHeaders().AcceptLanguage);
                headerPortion.Append(request.ContentLength == null ? "0" : ((long)request.ContentLength).ToString(CultureInfo.InvariantCulture));

                var md5 = request.Headers[HttpRequestHeader.ContentMd5.ToString()][0];
                headerPortion.Append(md5 ?? string.Empty);

                headerPortion.Append(request.GetTypedHeaders().ContentType);
            }
            headerPortion.Append(request.GetTypedHeaders().Date.HasValue ? request.GetTypedHeaders().Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            headerPortion.Append(request.GetTypedHeaders().IfModifiedSince);
            headerPortion.Append(request.GetTypedHeaders().IfMatch);
            headerPortion.Append(request.GetTypedHeaders().IfNoneMatch);
            headerPortion.Append(request.GetTypedHeaders().IfUnmodifiedSince);
            headerPortion.Append(request.GetTypedHeaders().Range);
            return headerPortion.ToString();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "The azure specification normalizes on lower case.")]
        public static string CanonicalizeResource(this HttpRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var canonicalizedResource = new StringBuilder();

            canonicalizedResource.Append("/");
            canonicalizedResource.Append(request.Host.ToString().ToLowerInvariant()); // We are using the host name rather than an account owner because that is too azure specific.
            canonicalizedResource.Append(WebUtility.UrlEncode(request.Path));

            if (request.Query.Any())
            {
                // We have query parameters
                NameValueCollection queryNameValueCollection = HttpUtility.ParseQueryString(request.QueryString.Value);

                var orderedQueryStringParameters = from q in queryNameValueCollection.AllKeys.Distinct() orderby q select q;

                foreach (string parameterName in orderedQueryStringParameters)
                {
                    canonicalizedResource.Append("\n");
                    canonicalizedResource.Append(parameterName);
                    canonicalizedResource.Append(":");
                    canonicalizedResource.Append(queryNameValueCollection[parameterName]);
                }
            }

            return canonicalizedResource.ToString();
        }
    }
}
