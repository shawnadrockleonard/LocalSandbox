using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityServerTester.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly ILogger _logger;

        public AccountController(ILogger<AccountController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var redirectUrl = Url.Content("~/");
            var challenge = Challenge(
                new AuthenticationProperties { RedirectUri = redirectUrl },
                "oidc"
                //WsFederationDefaults.AuthenticationScheme
                );
            return challenge;
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var redirectUrl = Url.Content("~/");
            return SignOut(
                new AuthenticationProperties { RedirectUri = redirectUrl },
                "oidc"
                //WsFederationDefaults.AuthenticationScheme
                );
        }
    }
}
