using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using IdentityServerTester.Helpers;
using IdentityServerTester.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace IdentityServerTester.Extensions
{
    public class TelemetryLoggingMiddleware
    {
        const string RoleTypeName = "Telemetry";
        private readonly RequestDelegate next;

        public TelemetryLoggingMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            await InvokeLogAsync(context);
        }

        public async Task InvokeLogAsync(HttpContext context)
        {
            var displayUrl = context.Request.GetDisplayUrl().Split('?')?[0];

            LogHelper.Log(new LogEntry
            {
                Type = LogEntryType.Telemetry,
                Operation = $"{RoleTypeName} => {displayUrl}",
                OperationStatusType = OperationStatusType.Unknown,
                OperationProperties = new[]
                {
                    "LoggingMiddleware",
                    $"Display URL: {displayUrl}"
                }
            },
            context);

            // Call the next delegate/middleware in the pipeline
            await next(context);
        }
    }
}
