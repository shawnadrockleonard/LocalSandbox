using IdentityServerTester.Helpers;
using IdentityServerTester.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace IdentityServerTester.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            var username = HttpContext.User?.Identity?.Name;
            LogHelper.Log(new LogEntry
            {
                Operation = "TestController/Get",
                Type = LogEntryType.Debug,
                OperationProperties = new[] { "hello", username }
            }, HttpContext);
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
