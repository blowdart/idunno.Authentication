using System.Security.Claims;

using Microsoft.AspNetCore.Authorization;

using idunno.Authentication.SharedKey;
using idunno.Authentication.SharedKey.Sample;

var keyResolver = new KeyResolver();
KeyResolver.Add("key #1");
KeyResolver.Add("key #2");

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(SharedKeyAuthenticationDefaults.AuthenticationScheme)
    .AddSharedKey(options =>
    {
        options.KeyResolver = KeyResolver.GetKey;
        options.Events = new SharedKeyAuthenticationEvents
        {
            OnValidateSharedKey = IdentityBuilder.OnValidateSharedKey
        };
    });
builder.Services.AddAuthorization();

builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/echo", [Authorize] (ClaimsPrincipal user) => new Message(null, ClaimsHelper.ToDictionary(user.Claims)));
app.MapGet("/echo/{message}", [Authorize] (ClaimsPrincipal user, string message) => new Message(message, ClaimsHelper.ToDictionary(user.Claims)));

app.MapRazorPages();

app.Run();

internal record Message(string? EchoedMessage, IDictionary<string, string> Claims);

internal class IdentityBuilder
{
    public static Task OnValidateSharedKey(ValidateSharedKeyContext context)
    {
        var claims = new[]
        {
            new Claim("keyId", context.KeyId, ClaimValueTypes.String, context.Options.ClaimsIssuer)
        };

        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
        context.Success();

        return Task.CompletedTask;
    }
}

internal static class ClaimsHelper
{ 
    public static IDictionary<string, string> ToDictionary(IEnumerable<Claim> claims)
    { 
        var claimsDictionary = new Dictionary<string, string>();

        foreach (var claim in claims)
        {
            claimsDictionary.Add(claim.Type, claim.Value);
        }

        return claimsDictionary;
    }
}