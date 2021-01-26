using IdentityServerTester.Extensions;
using IdentityServerTester.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.IO;

namespace IdentityServerTester
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        private readonly IWebHostEnvironment HostingEnvironment;

        public Startup(IWebHostEnvironment environment)
        {
            HostingEnvironment = environment;
            Configuration = BuildConfiguration();
        }

        /// <summary>
        /// Build configuration from AppSettings, Environment Variables, Azure Key Valut and (User Secrets - DEV only).
        /// </summary>
        /// <returns><see cref="IConfiguration"/></returns>
        private IConfiguration BuildConfiguration()
        {
            var configurationBuilder = new ConfigurationBuilder();
            configurationBuilder.SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .AddUserSecrets(typeof(Startup).Assembly)
                .AddAzureKeyVaultIfAvailable();

            if (HostingEnvironment.IsDevelopment())
            {
                // Re-add User secrets so it takes precedent for local development
                configurationBuilder.AddUserSecrets(typeof(Startup).Assembly);
            }

            return configurationBuilder.Build();
        }


        public void ConfigureServices(IServiceCollection services)
        {
            services.AddTransient<IAppSettingEntity, AppSettingEntity>(config =>
            {
                var connection = Configuration.Get<AppSettingEntity>();
                return connection;
            });

            var authentication = Configuration.GetSection("Authentication");
            var defaultAuth = authentication["Default"];

            // Configure application insights
            services.AddApplicationInsights(Configuration);

            if (defaultAuth == WsFederationDefaults.AuthenticationScheme)
            {
                var wsFedSection = Configuration.GetSection("Authentication:WsFed");
                services.AddAuthentication(sharedOptions =>
                {
                    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    sharedOptions.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
                }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddWsFederation(options =>
                {
                    options.Wtrealm = wsFedSection["Wtrealm"];
                    options.MetadataAddress = wsFedSection["MetadataAddress"];
                    options.Events = new WsFederationEvents
                    {
                        OnTicketReceived = async context =>
                        {
                            var claims = context.Principal?.Claims;

                            context.Success();
                        }
                    };
                });
            }
            else
            {
                services.AddOpenId(Configuration);
            }

            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_3_0);
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseExceptionHandlerMiddleware();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthorization();

            // enable serilog
            app.UseTelemetryLoggingMiddleware();


            app.UseEndpoints(endpoints => {

                endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
