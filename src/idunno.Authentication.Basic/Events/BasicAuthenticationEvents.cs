// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.


#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace idunno.Authentication.Basic
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// This default implementation of the IBasicAuthenticationEvents may be used if the
    /// application only needs to override a few of the interface methods.
    /// This may be used as a base class or may be instantiated directly.
    /// </summary>
    public class BasicAuthenticationEvents
    {
        /// <summary>
        /// A delegate assigned to this property will be invoked when the authentication handler fails and encounters an exception.
        /// </summary>
        public Func<BasicAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked when the credentials need validation.
        /// </summary>
        /// <remarks>
        /// You must provide a delegate for this property for authentication to occur.
        /// In your delegate you should construct an authentication principal from the user details,
        /// attach it to the context.Principal property and finally call context.Success();
        /// </remarks>
        public Func<ValidateCredentialsContext, Task> OnValidateCredentials { get; set; } = context => Task.CompletedTask;

        public virtual Task AuthenticationFailed(BasicAuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task ValidateCredentials(ValidateCredentialsContext context) => OnValidateCredentials(context);
    }
}
