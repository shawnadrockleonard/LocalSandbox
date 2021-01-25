using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebIdentityServer.Helpers
{
    [SuppressMessage("Minor Code Smell", "S3925:Update this implementation of 'ISerializable' to conform to the recommended serialization pattern", Justification = "'Exception' implements 'ISerializable' so 'ISerializable' can be removed from the inheritance list")]
    public class IdentityServerException : Exception
    {
        public IdentityServerException()
        {
        }

        public IdentityServerException(string message) : base(message)
        {
        }

        public IdentityServerException(string message, string paramName) : base($"{message} using parameter name {paramName}")
        {
        }

        public IdentityServerException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected IdentityServerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
