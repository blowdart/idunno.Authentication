
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace idunno.Authentication.Demo.Controllers
{
    public class HomeController : Controller
    {
        [Route("/")]
        [Route("/[action]")]
        public IActionResult Index()
        {
            return View();
        }

        [Route("/[action]")]
        [Authorize(Policy = "AlwaysFail")]
        public IActionResult AlwaysFail()
        {
            return View();
        }
    }
}
