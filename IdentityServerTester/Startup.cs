using System;
using System.Net.Http;
using System.Security.Claims;
using System.Linq;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.ApplicationInsights.Extensibility;
using Serilog.Events;
using System.IO;

namespace IdentityServerTester
{
    public class Startup
    {
        private const string AzureKeyVaultKey = "AzureKeyVault";
        private const string AzureKeyValutUrlKey = "Vault";

        public IConfiguration Configuration { get; }
        private readonly IHostingEnvironment HostingEnvironment;

        public Startup(IHostingEnvironment environment)
        {
            HostingEnvironment = environment;
            Configuration = BuildConfiguration();

            Log.Logger = GetLogger();
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
                .AddUserSecrets(typeof(Startup).Assembly);

            var configurationRoot = configurationBuilder.Build();
            var keyVaultConfigurationSection = configurationRoot.GetSection(AzureKeyVaultKey);

            AddAzureKeyVaultIfAvailable(configurationBuilder, keyVaultConfigurationSection);

            if (HostingEnvironment.IsDevelopment())
            {
                // Re-add User secrets so it takes precedent for local development
                configurationBuilder.AddUserSecrets(typeof(Startup).Assembly);
            }

            return configurationBuilder.Build();
        }


        public void ConfigureServices(IServiceCollection services)
        {

            //JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            var authentication = Configuration.GetSection("Authentication");
            var defaultAuth = authentication["Default"];


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
                });
            }
            else
            {
                var oidcSection = Configuration.GetSection("Authentication:oidc");
                services.AddAuthentication(sharedOptions =>
                {
                    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    sharedOptions.DefaultChallengeScheme = "oidc";
                }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = HostingEnvironment.IsDevelopment() ? oidcSection["LocalAuthority"] : oidcSection["Authority"];
                    options.RequireHttpsMetadata = true;
                    options.ClientId = oidcSection["ClientId"];
                    options.ClientSecret = oidcSection["ClientSecret"];
                    options.SaveTokens = true;
                    //options.Scope.Add("openid");
                    //options.Scope.Add("profile");
                    //options.Scope.Add("email");
                    //options.Scope.Add("secureapi");
                    options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
                    {
                        OnTokenValidated = async context =>
                        {
                            var accessToken = context.SecurityToken;
                            var client = new HttpClient();
                            var discovery = await client.GetDiscoveryDocumentAsync(options.Authority);
                            if (discovery.IsError) throw new Exception(discovery.Error);


                            var userInfoResponse = await client.GetUserInfoAsync(new UserInfoRequest
                            {
                                Address = discovery.UserInfoEndpoint,
                                Token = accessToken.RawData
                            });

                            if (context.Principal.Identity is ClaimsIdentity identity)
                            {
                                if (userInfoResponse?.IsError == true)
                                {
                                    var nameIdentity = accessToken.Claims.FirstOrDefault(fd => fd.Type.Equals("email", StringComparison.OrdinalIgnoreCase));
                                    if (nameIdentity != null)
                                    {
                                        identity.AddClaim(new Claim("name", nameIdentity.Value));
                                    }
                                    var emailIdentity = accessToken.Claims.FirstOrDefault(fd => fd.Type.Equals("email", StringComparison.OrdinalIgnoreCase));
                                    if (emailIdentity != null)
                                    {
                                        identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", emailIdentity.Value));
                                        identity.AddClaim(new Claim("Email", emailIdentity.Value));
                                    }
                                }
                                else
                                {
                                    var email = userInfoResponse.Claims?.FirstOrDefault(s => s.Type.Equals("name", StringComparison.OrdinalIgnoreCase))?.Value;
                                    identity.AddClaim(new Claim("name", userInfoResponse.Claims?.FirstOrDefault(s => s.Type.Equals("name", StringComparison.OrdinalIgnoreCase))?.Value));
                                    identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", email));
                                    identity.AddClaim(new Claim("Email", email));
                                }
                            }

                            context.Success();
                        }
                    };
                });
            }

            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_2);
        }

        /// <summary>
        /// if Azure Key Valus is available, reads configuration values from the Azure KeyVault.
        /// </summary>
        /// <param name="builder"><see cref="IConfigurationBuilder"/></param>
        /// <param name="keyVaultConfiguration">key vaule configuration properties</param>
        private static void AddAzureKeyVaultIfAvailable(IConfigurationBuilder builder, IConfiguration keyVaultConfiguration)
        {
            string clientId = keyVaultConfiguration["ClientId"];
            string vaultUrl = keyVaultConfiguration[AzureKeyValutUrlKey];

            if (string.IsNullOrEmpty(vaultUrl))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                // Try to access the Key Vault utilizing the Managed Service Identity of the running resource/process
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var vaultClient =
                    new KeyVaultClient(
                        new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                builder.AddAzureKeyVault(vaultUrl, vaultClient, new DefaultKeyVaultSecretManager());
            }
            else
            {
                // Allow to override the MSI or for local dev
                builder.AddAzureKeyVault(vaultUrl, clientId, keyVaultConfiguration["ClientSecret"]);
            }
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }

        /// <summary>
        /// Sets up Logging if AppInsights Instrumentation Key is avaialble
        /// </summary>
        private ILogger GetLogger()
        {
            var loggerConfiguration = new LoggerConfiguration().WriteTo.Logger(consoleLogger =>
            {
                consoleLogger.MinimumLevel.Information()
                        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                        .MinimumLevel.Override("System", LogEventLevel.Warning)
                        .WriteTo.Console();
            });

            var applicationInsightsInstrumentationKey = Configuration.GetValue<string>("ApplicationInsights:InstrumentationKey");
            var applicationInsightsEndpointAddress = Configuration.GetValue<string>("ApplicationInsights:EndpointAddress");

            Guid.TryParse(applicationInsightsInstrumentationKey, out var result);
            Uri.TryCreate(applicationInsightsEndpointAddress, UriKind.Absolute, out var validatedUri);

            if (result.ToString() == "00000000-0000-0000-0000-000000000000" || validatedUri == null)
            {
                Serilog.Debugging.SelfLog.Enable((msg) => { TrackAuditEvent(msg); });
                return loggerConfiguration.CreateLogger();
            }

            TelemetryConfiguration.Active.InstrumentationKey = applicationInsightsInstrumentationKey;
            TelemetryConfiguration.Active.TelemetryChannel.EndpointAddress = applicationInsightsEndpointAddress;

            var loggingSection = Configuration.GetSection("Logging");
            Enum.TryParse(loggingSection["Level"], true, out LogEventLevel loggingLevel);

            var logger = loggerConfiguration
                           .WriteTo.Logger(auditLogger =>
                           {
                               auditLogger.WriteTo
                                  .ApplicationInsights(TelemetryConfiguration.Active, TelemetryConverter.Events, restrictedToMinimumLevel: loggingLevel)
                                   .Enrich
                                   .FromLogContext();
                           })
                           .CreateLogger();

            Serilog.Debugging.SelfLog.Enable((msg) => { TrackAuditEvent(msg); });
            return logger;
        }

        private void TrackAuditEvent(string msg)
        {
            System.Diagnostics.Trace.TraceInformation(msg);
        }
    }
}
