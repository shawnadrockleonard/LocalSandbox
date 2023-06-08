using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Serilog;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServerTester
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "IdentityServer Tester";
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            var builder = WebHost.CreateDefaultBuilder(args)
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .ConfigureKestrel((context, options) =>
                {
                    /* Set properties and call methods on options */
                });

            builder.UseSerilog();

            return builder.Build();
        }

        private static X509Certificate2 ReadCertificate(string certificateThumbprint)
        {
            using var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
            var certSigningCredentials = certCollection?[0];
            return certSigningCredentials;
        }

    }
}
