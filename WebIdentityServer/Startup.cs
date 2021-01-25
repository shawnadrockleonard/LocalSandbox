using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using WebIdentityServer.Extensions;
using WebIdentityServer.Services;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Events;


namespace WebIdentityServer
{
    [SuppressMessage("Major Code Smell", "S3900:Arguments of public methods should be validated against null", Justification = "Arguments in this class are injected by framework, no need to check for null")]
    [SuppressMessage("Critical Code Smell", "S1200:Classes should not be coupled to too many other classes", Justification = "Dependency injection makes will not allow to reduce dependency on other classes.")]
    [SuppressMessage("Minor Code Smell", "S2325: Make methods static.", Justification = "Identity")]
    public class Startup
    {
        private const string AzureKeyVaultKey = "AzureKeyVault";
        private const string AzureKeyValutUrlKey = "Vault";

        public IHostingEnvironment HostingEnvironment { get; }
        public IConfiguration Configuration { get; }

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
            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_2);
            services.Configure<IISOptions>(options =>
            {
                options.AutomaticAuthentication = false;
                options.AuthenticationDisplayName = "Windows";
            });

            services.AddTransient<IHttpContextAccessor, HttpContextAccessor>();
            services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
            .AddE2EProcessing(Configuration)
            .AddSaml2PIdentityServerCertificates(Configuration)
            .AddSaml2PIdentityServer(Configuration)
            .AddInMemoryIdentityResources(Config.GetIdentityResources())
            .AddInMemoryApiResources(Config.GetApis())
            .AddInMemoryClients(Config.GetClients());

            services.AddAuthentication()
            .AddAzureAdSaml2P(Configuration)
            .AddAdfsOpenId(Configuration)
            .AddAdfsWsFed(Configuration)
            .AddAzureAdOpenId(Configuration);

            services.AddCors();
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

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            app.UseIdentityServer();
            app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().AllowCredentials());
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
                consoleLogger.MinimumLevel.Information().WriteTo.Console();
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

        private static void TrackAuditEvent(string msg)
        {
            System.Diagnostics.Trace.TraceInformation(msg);
        }
    }
}
