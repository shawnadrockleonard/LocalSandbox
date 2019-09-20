using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace IdentityServerTester
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Federation IdentityServer4";
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            return new WebHostBuilder()
                   .UseContentRoot(Directory.GetCurrentDirectory())
                   .UseIISIntegration()
                   .ConfigureLogging(factory =>
                   {
                       factory.AddConsole();
                       factory.AddDebug();
                       factory.AddFilter("Console", level => level >= LogLevel.Information);
                       factory.AddFilter("Debug", level => level >= LogLevel.Information);
                   })
                   .UseKestrel(options =>
                   {
                       options.Listen(IPAddress.Loopback, 44358, listenOptions =>
                       {
                           // Configure SSL
                           var serverCertificate = ReadCertificate("D61977118A763F4BB30E5919929F727FA9336C06");
                           listenOptions.UseHttps(serverCertificate);
                       });
                   })
                   .UseStartup<Startup>()
                   .UseSerilog()
                   .Build();
        }

        private static X509Certificate2 ReadCertificate(string certificateThumbprint)
        {
            using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
                var certSigningCredentials = certCollection?[0];
                return certSigningCredentials;
            }
        }

    }
}
