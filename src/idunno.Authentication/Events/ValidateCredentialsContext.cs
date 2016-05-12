// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication
{
    public class ValidateCredentialsContext : BaseBasicAuthenticationContext
    {
        /// <summary>
        /// Creates a new instance of <see cref="ValidateCredentialsContext"/>.
        /// </summary>
        /// <param name="context">The HttpContext the validate context applies too.</param>
        /// <param name="options">The <see cref="BasicAuthenticationOptions"/> for the instance of 
        /// <see cref="BasicAuthenticationMiddleware"/> is creating this instance.</param>
        public ValidateCredentialsContext(HttpContext context, BasicAuthenticationOptions options)
            : base(context, options)
        {
        }

        /// <summary>
        /// The user name to validate.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The password to validate.
        /// </summary>
        public string Password { get; set; }

    }
}
