using System;
using System.Data.SqlClient;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using IdentityServerTester.Helpers;
using Microsoft.AspNetCore.Http;

namespace IdentityServerTester.Extensions
{
    /// <summary>
    /// This exception handler middleware is used to translate unhanbled exception (500 internal server error) to more useful status codes for the client
    /// and developers to troubleshoot.  This is an initial list of handled errors.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class ExceptionHandlerMiddleware
    {
        private readonly RequestDelegate next;

        public ExceptionHandlerMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Acceptable to catch all errors for general code")]
        public async Task Invoke(HttpContext httpContext)
        {
            try
            {
                await next(httpContext);
            }
            catch (HttpStatusCodeException hsce)
            {
                string message = string.Empty;

                if (!string.IsNullOrEmpty(hsce.Message))
                {
                    message = $"trace ID: '{hsce.Message}'";
                }

                await ProcessExceptionAsync(httpContext, hsce.StatusCode, hsce, message);
            }
            catch (Exception ex)
            {
                await ProcessExceptionAsync(httpContext, StatusCodes.Status500InternalServerError, ex, "Application Internal Error");
            }
        }

        public static async Task ProcessExceptionAsync(HttpContext httpContext, int statusCode, Exception exception, string message)
        {
            if (httpContext.Response.HasStarted)
            {
                throw exception;
            }

            LogHelper.ProcessException(httpContext, statusCode, exception, message);

            httpContext.Response.Clear();
            httpContext.Response.StatusCode = statusCode;

            await httpContext.Response.WriteAsync(message);
        }
    }
}
