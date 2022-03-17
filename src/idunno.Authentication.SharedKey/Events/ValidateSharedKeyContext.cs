// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.SharedKey
{
    public class ValidateSharedKeyContext : ResultContext<SharedKeyAuthenticationOptions>
    {

        /// <summary>
        /// Creates a new instance of <see cref="ValidateSharedKeyContext"/>.
        /// </summary>
        /// <param name="context">The HttpContext the validate context applies too.</param>
        /// <param name="scheme">The scheme used when the shared key authentication handler was registered.</param>
        /// <param name="options">The <see cref=SharedKeyAuthenticationOptions"/> for the instance of
        /// <see cref="SharedKeyAuthenticationHander"/> creating this instance.</param>
        /// <param name="ticket">Contains the initial values for the identity.</param>
        public ValidateSharedKeyContext(
            HttpContext context,
            AuthenticationScheme scheme,
            SharedKeyAuthenticationOptions options)
            : base(context, scheme, options)
        {
        }

        /// <summary>
        /// The key identifier to validate.
        /// </summary>
        public string KeyId { get; set; }
    }
}
