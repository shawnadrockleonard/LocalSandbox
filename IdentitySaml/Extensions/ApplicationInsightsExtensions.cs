using System;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Extensions.Logging;

namespace IdentityServerTester.Extensions
{
    public static class ApplicationInsightsExtensions
    {
        private static bool hasApplicationInsights = true;

        /// <summary>
        /// Sets up Logging if AppInsights Instrumentation Key is avaialble
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void AddApplicationInsights(this IServiceCollection services, IConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var applicationInsightsInstrumentationKey = configuration.GetValue("ApplicationInsights:InstrumentationKey", Guid.Empty);
            var applicationInsightsEndpointAddress = configuration.GetValue<string>("ApplicationInsights:EndpointAddress");
            var loggingSection = configuration.GetSection("Logging");
            Enum.TryParse(loggingSection["Level"], true, out LogEventLevel loggingLevel);
            Uri.TryCreate(applicationInsightsEndpointAddress, UriKind.Absolute, out var validatedUri);


            if (applicationInsightsInstrumentationKey == Guid.Empty || validatedUri == null)
            {
                System.Diagnostics.Trace.TraceError($"Application Insights properties missing from JSON or Azure Key Vault.");
                hasApplicationInsights = false;
            }
            else
            {
                services.AddApplicationInsightsTelemetry((options) =>
                {
                    options.InstrumentationKey = applicationInsightsInstrumentationKey.ToString();
                    options.EndpointAddress = applicationInsightsEndpointAddress;
                    options.EnableAdaptiveSampling = false;
                    options.EnableAppServicesHeartbeatTelemetryModule = false;
                    options.EnablePerformanceCounterCollectionModule = false;
                    options.EnableHeartbeat = false;
                    options.EnableDebugLogger = false;
                });
            }

            services.AddSingleton(implementationInstance =>
            {
                var logger = new LoggerConfiguration()
                        .WriteTo.Logger(consoleLogger =>
                        {
                            consoleLogger.MinimumLevel.Information()
                            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                            .MinimumLevel.Override("System", LogEventLevel.Warning)
                            .WriteTo.Console();
                        });


                if (hasApplicationInsights)
                {
                    logger = logger.WriteTo.Logger(eventLogger =>
                    {
                        var telemetryConfiguration = implementationInstance.GetRequiredService<TelemetryConfiguration>();
                        eventLogger.WriteTo
                        .ApplicationInsights(telemetryConfiguration, TelemetryConverter.Events, restrictedToMinimumLevel: loggingLevel)
                        .Enrich
                        .FromLogContext();
                    });
                }

                Log.Logger = logger.CreateLogger();
                Serilog.Debugging.SelfLog.Enable((msg) => { TrackAuditEvent(implementationInstance, msg); });
                return Log.Logger;
            });

            services.AddSingleton<ILoggerFactory>(provider =>
            {
                var logger = provider.GetRequiredService<Serilog.ILogger>();
                return new SerilogLoggerFactory(logger, true);
            });
        }

        public static void TrackAuditEvent(IServiceProvider implementationInstance, string msg)
        {
            if (implementationInstance == null)
            {
                throw new ArgumentNullException(nameof(implementationInstance));
            }

            System.Diagnostics.Trace.TraceError(msg);
        }
    }
}
