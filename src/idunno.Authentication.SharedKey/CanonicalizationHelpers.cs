// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Web;

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace idunno.Authentication.SharedKey
{
    internal static class CanonicalizationHelpers
    {
        public static string CanonicalizeHeaders(this HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.Headers == null)
            {
                throw new NullReferenceException("Request has not headers.");
            }

            var canonicalizedHeaderBuilder = new CanonicalizedStringBuilder();
            canonicalizedHeaderBuilder.Append(request.Method.ToString().ToUpperInvariant());
            if (request.Content == null || request.Content.Headers == null)
            {
                canonicalizedHeaderBuilder.Append(string.Empty); // Encoding
                canonicalizedHeaderBuilder.Append(string.Empty); // Language
                canonicalizedHeaderBuilder.Append(0);            // Length
                canonicalizedHeaderBuilder.Append(string.Empty); // MD5
                canonicalizedHeaderBuilder.Append(string.Empty); // Content-Type
            }
            else
            {
                canonicalizedHeaderBuilder.Append(request.Content.Headers.ContentEncoding);
                canonicalizedHeaderBuilder.Append(request.Content.Headers.ContentLanguage);
                canonicalizedHeaderBuilder.Append(request.Content.Headers == null ? "0" : ((long)request.Content.Headers.ContentLength).ToString(CultureInfo.InvariantCulture));
                canonicalizedHeaderBuilder.Append(request.Content.Headers.ContentMD5 == null ? string.Empty : Convert.ToBase64String(request.Content.Headers.ContentMD5));
                canonicalizedHeaderBuilder.Append(request.Content.Headers.ContentType);
            }
            canonicalizedHeaderBuilder.Append(request.Headers.Date.HasValue ? request.Headers.Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.IfModifiedSince.HasValue ? request.Headers.IfModifiedSince.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.IfMatch);
            canonicalizedHeaderBuilder.Append(request.Headers.IfNoneMatch);
            canonicalizedHeaderBuilder.Append(request.Headers.IfUnmodifiedSince.HasValue ? request.Headers.IfUnmodifiedSince.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.Range);

            return canonicalizedHeaderBuilder.ToString();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "The azure specification normalizes on lower case.")]
        public static string CanonicalizeResource(this HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var canonicalizedResourceBuilder = new StringBuilder();

            canonicalizedResourceBuilder.Append(request.RequestUri.AbsolutePath);

            if (request.RequestUri.Query.Length > 0 )
            {
                // We have query parameters
                NameValueCollection queryNameValueCollection = HttpUtility.ParseQueryString(request.RequestUri.Query);
                var sortedQueryNameValueList = new SortedList<string, string>(queryNameValueCollection.AllKeys.ToDictionary(k => k ?? string.Empty, k => queryNameValueCollection[k]));

                foreach (var keyValuePair in sortedQueryNameValueList)
                {
                    canonicalizedResourceBuilder.Append('\n');
                    canonicalizedResourceBuilder.Append(keyValuePair.Key.ToLowerInvariant());
                    canonicalizedResourceBuilder.Append(':');
                    canonicalizedResourceBuilder.Append(keyValuePair.Value);
                }
            }

            return canonicalizedResourceBuilder.ToString();
        }

        public static string CanonicalizeHeaders(this HttpRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var canonicalizedHeaderBuilder = new CanonicalizedStringBuilder();
            canonicalizedHeaderBuilder.Append(request.Method.ToString().ToUpperInvariant());
            if (request.Headers == null)
            {
                canonicalizedHeaderBuilder.Append(string.Empty); // Encoding
                canonicalizedHeaderBuilder.Append(string.Empty); // Language
                canonicalizedHeaderBuilder.Append(0);            // Length
                canonicalizedHeaderBuilder.Append(string.Empty); // MD5
                canonicalizedHeaderBuilder.Append(string.Empty); // Content-Type
            }
            else
            {
                canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.ContentEncoding].ToString());
                canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.ContentLanguage].ToString());
                canonicalizedHeaderBuilder.Append(request.ContentLength == null ? "0" : ((long)request.ContentLength).ToString(CultureInfo.InvariantCulture));
                canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.ContentMD5].ToString());
                canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.ContentType].ToString());
            }

            canonicalizedHeaderBuilder.Append(request.GetTypedHeaders().Date.HasValue ? request.GetTypedHeaders().Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.IfModifiedSince].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.IfMatch].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.IfNoneMatch].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.IfUnmodifiedSince].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers[HeaderNames.Range].ToString());

            return canonicalizedHeaderBuilder.ToString();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "The azure specification normalizes on lower case.")]
        public static string CanonicalizeResource(this HttpRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var canonicalizedResourceBuilder = new StringBuilder();

            canonicalizedResourceBuilder.Append(request.Path);

            if (request.Query.Any())
            {
                // We have query parameters
                NameValueCollection queryNameValueCollection = HttpUtility.ParseQueryString(request.QueryString.Value);
                var sortedQueryNameValueList = new SortedList<string, string>(queryNameValueCollection.AllKeys.ToDictionary(k => k ?? string.Empty, k => queryNameValueCollection[k]));

                foreach (var keyValuePair in sortedQueryNameValueList)
                {
                    canonicalizedResourceBuilder.Append('\n');
                    canonicalizedResourceBuilder.Append(keyValuePair.Key.ToLowerInvariant());
                    canonicalizedResourceBuilder.Append(':');
                    canonicalizedResourceBuilder.Append(keyValuePair.Value);
                }
            }

            return canonicalizedResourceBuilder.ToString();
        }
    }
}
