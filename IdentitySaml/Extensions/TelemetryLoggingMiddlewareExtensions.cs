using Microsoft.AspNetCore.Builder;


namespace IdentityServerTester.Extensions
{
    public static class TelemetryLoggingMiddlewareExtensions
    {
        public static IApplicationBuilder UseTelemetryLoggingMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TelemetryLoggingMiddleware>();
        }
    }
}
