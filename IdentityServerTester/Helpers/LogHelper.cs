using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Serilog.Context;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace IdentityServerTester.Helpers
{
    public static class LogHelper
    {
        const string RoleTypeName = "FederationTester";

        public static void LogTelemetry(LogEntry logEntry, HttpContext httpContext = null)
        {
            var userAgent = new StringValues("N/A");

            if (httpContext != null && httpContext.Request.Headers.ContainsKey("User-Agent"))
            {
                httpContext.Request.Headers.TryGetValue("User-Agent", out userAgent);
            }

            using (LogContext.PushProperty("UserAgent", userAgent))
            using (LogContext.PushProperty("Type", logEntry?.Type))
            using (LogContext.PushProperty("Operation", logEntry?.Operation))
            using (LogContext.PushProperty("OperationProperties", logEntry?.OperationProperties))
            using (LogContext.PushProperty("Role", RoleTypeName))
            {
                LogForType(logEntry);
            }
        }

        public static void Log(LogEntry logEntry, HttpContext httpContext = null)
        {
            if (logEntry == null)
            {
                throw new ArgumentException("can't be null", nameof(logEntry));
            }

            var instanceId = "N/A";
            var userPrincipalName = "N/A";
            var userAgent = new StringValues("N/A");
            var remoteIpAddress = "N/A";

            if (httpContext != null)
            {
                if (httpContext.Request.Headers.ContainsKey("User-Agent"))
                {
                    httpContext.Request.Headers.TryGetValue("User-Agent", out userAgent);
                }

                if (logEntry.Type == LogEntryType.Audit)
                {
                    instanceId = httpContext.TraceIdentifier;
                    userPrincipalName = httpContext.User?.Identity?.Name;
                    remoteIpAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                }
            }

            using (LogContext.PushProperty("InstanceId", instanceId))
            using (LogContext.PushProperty("UserAgent", userAgent))
            using (LogContext.PushProperty("Type", logEntry?.Type))
            using (LogContext.PushProperty("Operation", logEntry?.Operation))
            using (LogContext.PushProperty("OperationProperties", logEntry?.OperationProperties))
            using (LogContext.PushProperty("Role", RoleTypeName))
            using (LogContext.PushProperty("UPN", userPrincipalName))
            using (LogContext.PushProperty("RemoteIpAddress", remoteIpAddress))
            {
                LogForType(logEntry);
            }
        }

        [SuppressMessage("Major Code Smell", "S3994:URI Parameters should not be strings", Justification = "parameter contains key for value in configuration file")]
        public static void LogDestinationIpFromKeyVault(IConfiguration configuration, string configSectionKey, string vaultUrlKey)
        {
            if (configuration == null)
            {
                throw new ArgumentException("can't be null", nameof(configuration));
            }

            var configurationSection = configuration.GetSection(configSectionKey);
            var vaultUrl = configurationSection[vaultUrlKey];

            if (string.IsNullOrEmpty(vaultUrl))
            {
                return;
            }

            var uri = new Uri(vaultUrl);

            LogDestinationIPs(configSectionKey, uri);
        }

        private static void LogForType(LogEntry logEntry)
        {
            if (logEntry == null)
            {
                throw new ArgumentNullException(nameof(logEntry));
            }

            var msg = $"{RoleTypeName} => {logEntry?.Operation}";

            switch (logEntry.Type)
            {
                case LogEntryType.Debug:
                    Serilog.Log.Debug(msg);
                    break;
                case LogEntryType.Warn:
                    Serilog.Log.Warning(msg);
                    break;
                case LogEntryType.Error:
                    Serilog.Log.Error(msg);
                    break;
                case LogEntryType.Fatal:
                    Serilog.Log.Fatal(msg);
                    break;
                default:
                    Serilog.Log.Information(msg);
                    break;
            }
        }

        private static void LogDestinationIPs(string key, Uri uri)
        {
            LogDestinationIPs(key, uri.Host);
        }

        private static void LogDestinationIPs(string key, string hostNameOrAddress)
        {
            var hostAddresses = Dns.GetHostAddresses(hostNameOrAddress);
            var ipAddresses = new List<string>();

            foreach (var hostAddress in hostAddresses)
            {
                ipAddresses.Add(hostAddress.ToString());
            }

            if (ipAddresses.Count > 0)
            {
                Log(new LogEntry { Type = LogEntryType.Audit, Operation = $"Remote Connection IP for '{key}'", OperationProperties = ipAddresses.ToArray() });
            }
        }

        public static void ProcessException(HttpContext httpContext, int statusCode, Exception exception, string message)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException(nameof(httpContext));
            }

            Log(new LogEntry
            {
                Type = LogEntryType.Error,
                Operation = $"Failure with message '{message}'",
                OperationProperties = new[] {
                    $"Request status ({statusCode})",
                    $"Request method ({httpContext.Request.Method})",
                    $"Request path ({httpContext.Request?.Path.Value})",
                    $"Exception Message: {exception?.Message}",
                    $"Exception Stack: {exception?.StackTrace}"
                }
            });
        }
    }
}
