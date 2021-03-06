using System;
using System.Diagnostics.CodeAnalysis;

namespace IdentityServerTester.Extensions
{
    [SuppressMessage("Minor Code Smell", "S3925:Update this implementation of 'ISerializable' to conform to the recommended serialization pattern", Justification = "'Exception' implements 'ISerializable' so 'ISerializable' can be removed from the inheritance list")]
    [SuppressMessage("Minor Code Smell", "S4027:Implement the missing constructors for this exception", Justification = "Additional constructors not needed")]
    public class HttpStatusCodeException : Exception
    {
        /// <summary>
        /// for status codes, see https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.statuscodes
        /// </summary>
        public int StatusCode { get; set; }

        public HttpStatusCodeException(int statusCode)
        {
            StatusCode = statusCode;
        }

        public HttpStatusCodeException(int statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }

        public HttpStatusCodeException(int statusCode, string message, Exception innerException) : base(message, innerException)
        {
            StatusCode = statusCode;
        }
    }
}