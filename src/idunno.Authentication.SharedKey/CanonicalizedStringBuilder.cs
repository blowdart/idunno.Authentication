// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;

namespace idunno.Authentication.SharedKey
{
    /// <summary>
    /// Builds a canonicalized string by separating values with a newline character.
    /// </summary>
    internal class CanonicalizedStringBuilder
    {
        private readonly StringBuilder stringBuilder = new StringBuilder();

        public CanonicalizedStringBuilder()
        {
        }

        public CanonicalizedStringBuilder(string initialString)
        {
            Append(initialString);
        }

        public CanonicalizedStringBuilder Append(object value)
        {
            stringBuilder.Append(value);
            stringBuilder.Append('\n');

            return this;
        }

        public override string ToString()
        {
            return stringBuilder.ToString();
        }
    }
}
