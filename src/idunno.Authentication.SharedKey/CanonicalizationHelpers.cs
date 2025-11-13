// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections;
using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Web;

namespace idunno.Authentication.SharedKey
{
    internal static class CanonicalizationHelpers
    {
        public static string CanonicalizeHeaders(this HttpRequestMessage request)
        {
            ArgumentNullException.ThrowIfNull(request);
            ArgumentNullException.ThrowIfNull(request.Headers);

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
                canonicalizedHeaderBuilder.Append(request.Content.Headers?.ContentEncoding);
                canonicalizedHeaderBuilder.Append(request.Content.Headers?.ContentLanguage);
                canonicalizedHeaderBuilder.Append(request.Content.Headers == null ? "0" :
                                                  request.Content.Headers.ContentLength == null ? "0" : ((long)request.Content.Headers.ContentLength).ToString(CultureInfo.InvariantCulture));
                canonicalizedHeaderBuilder.Append(request.Content.Headers == null ? string.Empty :
                                                  request.Content.Headers.ContentMD5 == null ? string.Empty : Convert.ToBase64String(request.Content.Headers.ContentMD5));
                canonicalizedHeaderBuilder.Append(request.Content.Headers?.ContentType);
            }

            canonicalizedHeaderBuilder.Append(request.Headers.Date.HasValue ? request.Headers.Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.IfModifiedSince.HasValue ? request.Headers.IfModifiedSince.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.IfMatch);
            canonicalizedHeaderBuilder.Append(request.Headers.IfNoneMatch);
            canonicalizedHeaderBuilder.Append(request.Headers.IfUnmodifiedSince.HasValue ? request.Headers.IfUnmodifiedSince.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers.Range);

            return canonicalizedHeaderBuilder.ToString();
        }

        public static string CanonicalizeResource(this HttpRequestMessage request)
        {
            ArgumentNullException.ThrowIfNull(request);
            ArgumentNullException.ThrowIfNull(request.RequestUri);
            ArgumentNullException.ThrowIfNull(request.RequestUri.AbsolutePath);

            var canonicalizedResourceBuilder = new StringBuilder();

            canonicalizedResourceBuilder.Append(request.RequestUri.AbsolutePath);

            if (request.RequestUri.Query.Length > 0 )
            {
                // We have query parameters
                canonicalizedResourceBuilder.Append(CanonicalizeQueryString(request.RequestUri.Query));
            }

            return canonicalizedResourceBuilder.ToString();
        }

        public static string CanonicalizeHeaders(this HttpRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            ArgumentNullException.ThrowIfNull(request.GetTypedHeaders());
            if (!request.GetTypedHeaders().Date.HasValue)
            {
                throw new ArgumentNullException("request.GetTypedHeaders().Date");
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
                canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.ContentEncoding].ToString());
                canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.ContentLanguage].ToString());
                canonicalizedHeaderBuilder.Append(request.ContentLength == null ? "0" : ((long)request.ContentLength).ToString(CultureInfo.InvariantCulture));
                canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.ContentMD5].ToString());
                canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.ContentType].ToString());
            }

            canonicalizedHeaderBuilder.Append(request.GetTypedHeaders().Date.HasValue ? request.GetTypedHeaders().Date!.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.IfModifiedSince].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.IfMatch].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.IfNoneMatch].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.IfUnmodifiedSince].ToString());
            canonicalizedHeaderBuilder.Append(request.Headers?[HeaderNames.Range].ToString());

            return canonicalizedHeaderBuilder.ToString();
        }

        public static string CanonicalizeResource(this HttpRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);

            var canonicalizedResourceBuilder = new StringBuilder();

            canonicalizedResourceBuilder.Append(request.Path);

            if (request.QueryString.Value != null && request.Query.Count != 0)
            {
                canonicalizedResourceBuilder.Append(CanonicalizeQueryString(request.QueryString.Value));
            }

            return canonicalizedResourceBuilder.ToString();
        }

        private static string CanonicalizeQueryString(string queryString)
        {
            var queryStringBuilder = new StringBuilder();

            NameValueCollection queryNameValueCollection = HttpUtility.ParseQueryString(queryString);
            var sortedQueryNameValueList = new SortedList<string, string>(queryNameValueCollection.AllKeys.ToDictionary(k => k ?? string.Empty, k => queryNameValueCollection[k] ?? string.Empty));

            foreach (var keyValuePair in sortedQueryNameValueList)
            {
                queryStringBuilder.Append('\n');
                queryStringBuilder.Append(keyValuePair.Key.ToLowerInvariant());
                queryStringBuilder.Append(':');
                if (keyValuePair.Value == null || !keyValuePair.Value.Contains(',', StringComparison.InvariantCulture))
                {
                    queryStringBuilder.Append(keyValuePair.Value);
                }
                else
                {
                    // We have multiple values, all nicely separated by commas, but they're not sorted.
                    var values = new List<string?>(keyValuePair.Value.Split(',', StringSplitOptions.None));
                    values.Sort(new InvariantComparer());
                    queryStringBuilder.Append(string.Join(",", values));
                }
            }
            return queryStringBuilder.ToString();
        }
    }

    internal class InvariantComparer : IComparer<string?>
    {
        internal static readonly InvariantComparer Default = new InvariantComparer();

        private readonly CompareInfo _compareInfo;

        internal InvariantComparer()
        {
            _compareInfo = CultureInfo.InvariantCulture.CompareInfo;
        }

        public int Compare(string? a, string? b)
        {
            if (a is string sa && b is string sb)
                return _compareInfo.Compare(sa, sb);
            else
                return Comparer.Default.Compare(a, b);
        }
    }
}
