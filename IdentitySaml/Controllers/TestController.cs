using IdentityServerTester.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerTester.Controllers
{
    [Produces("application/json")]
    [Route("api/Test")]
    public class TestController : Controller
    {
        [Authorize]
        public IActionResult Get()
        {
            var user = HttpContext.User;
            LogHelper.Log(new LogEntry
            {
                Operation = "TestController/Get",
                Type = LogEntryType.Debug,
                OperationProperties = new[] { "hello", user.Identity?.Name }
            }, HttpContext);
            return Ok("Success");
        }
    }
}