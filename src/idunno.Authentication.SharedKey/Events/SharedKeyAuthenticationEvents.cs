// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace idunno.Authentication.SharedKey
{
    /// <summary>
    /// Events for SharedKeyAuthentication to allow a developer to customize user validation and the response to validation failures.
    /// </summary>
    public class SharedKeyAuthenticationEvents
    {
        /// <summary>
        /// /// A delegate assigned to this property will be invoked when the authentication handler fails and encounters an exception.
        /// </summary>
        public Func<SharedKeyAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked when a shared key has based normal validation, but where custom validation may be needed.
        /// </summary>
        /// <remarks>
        /// You must provide a delegate for this property for authentication to occur.
        /// In your delegate you should construct an authentication principal from the user details,
        /// attach it to the context.Principal property and finally call context.Success();
        /// </remarks>
        public Func<ValidateSharedKeyContext, Task> OnValidateSharedKey { get; set; } = context => Task.CompletedTask;

        public virtual Task AuthenticationFailed(SharedKeyAuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task ValidateSharedKey(ValidateSharedKeyContext context) => OnValidateSharedKey(context);
    }
}
