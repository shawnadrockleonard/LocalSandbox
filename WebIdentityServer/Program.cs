using System;
using System.IO;
using System.Resources;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Serilog;

[assembly: NeutralResourcesLanguage("en-US")]

namespace WebIdentityServer
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "IdentityServer4";
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            return WebHost.CreateDefaultBuilder(args)
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .ConfigureKestrel((context, options) => { /* Set properties and call methods on options */ })
                .UseSerilog()
                .Build();
        }
    }
}
