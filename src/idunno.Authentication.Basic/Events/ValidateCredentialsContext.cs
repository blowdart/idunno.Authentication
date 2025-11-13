// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETSTANDARD2_0
#nullable enable
#endif

using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace idunno.Authentication.Basic
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Creates a new instance of <see cref="ValidateCredentialsContext"/>.
    /// </summary>
    /// <param name="context">The HttpContext the validate context applies too.</param>
    /// <param name="scheme">The scheme used when the Basic Authentication handler was registered.</param>
    /// <param name="options">The <see cref="BasicAuthenticationOptions"/> for the instance of
    /// <see cref="BasicAuthenticationHandler"/> creating this instance.</param>
    /// <param name="ticket">Contains the initial values for the identity.</param>
    public class ValidateCredentialsContext : ResultContext<BasicAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateCredentialsContext"/> class.
        /// </summary>
        /// <param name="username">The user name to validate.</param>
        /// <param name="password">The password to validate, if any.</param>
        /// <param name="context">The HttpContext the validate context applies too.</param>
        /// <param name="scheme">The scheme used when the Basic Authentication handler was registered.</param>
        /// <param name="options">The <see cref="BasicAuthenticationOptions"/> for the instance of
        /// <see cref="BasicAuthenticationHandler"/> creating this instance.</param>
        [SuppressMessage("Style", "IDE0290:Use primary constructor", Justification = "Username is required, and required is not supported on NETSTANDARD2.0")]
        public ValidateCredentialsContext(
            string username,
            string? password,
            HttpContext context,
            AuthenticationScheme scheme,
            BasicAuthenticationOptions options)
            : base(context, scheme, options)
        {
            Username = username;
            Password = password;

        }

        /// <summary>
        /// The user name to validate.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The password to validate.
        /// </summary>
        public string? Password { get; set; }
    }
}
