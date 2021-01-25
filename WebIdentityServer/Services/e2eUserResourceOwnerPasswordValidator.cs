using System.Threading.Tasks;
using WebIdentityServer.Helpers;
using IdentityModel;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;

namespace WebIdentityServer.Services
{
    /// <summary>
    /// Resource owner password validator for test users
    /// </summary>
    /// <seealso cref="IResourceOwnerPasswordValidator" />
    public class E2EUserResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private readonly IE2EUserStore users;
        private readonly ISystemClock clock;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestUserResourceOwnerPasswordValidator"/> class.
        /// </summary>
        /// <param name="users">The users.</param>
        /// <param name="clock">The clock.</param>
        public E2EUserResourceOwnerPasswordValidator(IE2EUserStore users, ISystemClock clock)
        {
            this.users = users;
            this.clock = clock;
        }

        /// <summary>
        /// Validates the resource owner password credential
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            if (users.ValidateCredentials(context.UserName, context.Password))
            {
                var user = users.FindByUsername(context.UserName);
                context.Result = new GrantValidationResult(
                    user.SubjectId ?? throw new IdentityServerException("Subject ID not set", nameof(user.SubjectId)),
                    OidcConstants.AuthenticationMethods.Password, clock.UtcNow.UtcDateTime,
                    user.Claims);
            }

            return Task.CompletedTask;
        }
    }
}
