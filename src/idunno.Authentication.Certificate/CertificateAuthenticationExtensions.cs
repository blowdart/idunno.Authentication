﻿// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;

using idunno.Authentication.Certificate;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Extension methods to add Certificate authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class CertificateAuthenticationAppBuilderExtensions
    {
        public static AuthenticationBuilder AddCertificate(this AuthenticationBuilder builder)
            => builder.AddCertificate(CertificateAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddCertificate(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddCertificate(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddCertificate(this AuthenticationBuilder builder, Action<CertificateAuthenticationOptions> configureOptions)
            => builder.AddCertificate(CertificateAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddCertificate(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<CertificateAuthenticationOptions> configureOptions)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddScheme<CertificateAuthenticationOptions, CertificateAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}