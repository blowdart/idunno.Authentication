// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "MD5 is part of the HTTP spec.", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.Test.SharedKeyHttpMessageHandlerTests.Md5IsAddedIfBodyIsPresentAndNotChunked~System.Threading.Tasks.Task")]
