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
            return WebHost.CreateDefaultBuilder(args)
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .ConfigureKestrel((context, options) =>
                {
                    /* Set properties and call methods on options */

                    //options.Listen(IPAddress.Loopback, 44358, listenOptions =>
                    //{
                    //    // Configure SSL
                    //    var serverCertificate = ReadCertificate("D61977118A763F4BB30E5919929F727FA9336C06");
                    //    listenOptions.UseHttps(serverCertificate);
                    //});
                })
                .UseSerilog()
                .Build();
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
