using System.ComponentModel.DataAnnotations;
using System.Net;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;


using idunno.Authentication.SharedKey;
using idunno.Authentication.SharedKey.Sample;

namespace idunno.Authentication.SharedSecret.Sample.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        [Display(Name = "Key Identifier:")]
        public string KeyIdentifier { get; set; } = string.Empty;

        [BindProperty]
        [Display(Name = "Message:")]
        public string? Message { get; set; }

        public List<SelectListItem> KnownKeyIdentifiers = KeyResolver.Keys.Select(k => new SelectListItem { Value = k.Key + ":" + Convert.ToHexString(k.Value), Text = k.Key }).ToList();

        public HttpStatusCode? ResponseCode;
        public string? ResponseBody;

        public IndexModel()
        {
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost()
        {
            var requestDestination = string.Concat(Request.Scheme, "://", Request.Host.ToUriComponent(), Request.PathBase.ToUriComponent(), "/echo");
            if (!string.IsNullOrEmpty(Message))
            {
                requestDestination = string.Concat(requestDestination, "/", Uri.EscapeDataString(Message));
            }

            var keyIdFromModel = KeyIdentifier[..(KeyIdentifier.IndexOf(':', StringComparison.OrdinalIgnoreCase))];

            var httpHanderPipeline = new SharedKeyHttpMessageHandler(keyIdFromModel, KeyResolver.GetKey(keyIdFromModel))
            {
                InnerHandler = new HttpClientHandler()
            };

            using var httpClient = new HttpClient(httpHanderPipeline);
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, requestDestination);
            var response = await httpClient.SendAsync(httpRequestMessage);

            ResponseCode = response.StatusCode;
            ResponseBody = await response.Content.ReadAsStringAsync();

            return Page();
        }
    }
}