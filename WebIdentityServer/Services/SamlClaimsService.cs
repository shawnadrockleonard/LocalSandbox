using System;
using System.Linq;
using System.Threading.Tasks;
using WebIdentityServer.Helpers;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace WebIdentityServer.Services
{
    internal class SamlClaimsService : IProfileService
    {
        /// <summary>
        /// The logger
        /// </summary>
        protected readonly ILogger logger;

        /// <summary>
        /// HttpContext Accessor for Claim discovery
        /// </summary>
        protected readonly IHttpContextAccessor httpContextAccessor;

        /// <summary>
        /// The users
        /// </summary>
        protected readonly E2EUserStore users;

        /// <summary>
        /// Initializes a new instance of the <see cref="SamlClaimsService"/> class.
        /// </summary>
        /// <param name="users">The users.</param>
        /// <param name="logger">The logger.</param>
        public SamlClaimsService(IHttpContextAccessor httpContextAccessor, E2EUserStore users, ILogger<SamlClaimsService> logger)
        {
            this.httpContextAccessor = httpContextAccessor;
            this.users = users;
            this.logger = logger;
        }

        /// <summary>
        /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            context.LogProfileRequest(logger);

            if (context.RequestedClaimTypes.Any())
            {
                var user = users.FindBySubjectId(context.Subject.GetSubjectId());
                if (user != null)
                {
                    context.AddRequestedClaims(user.Claims);
                    if (!TrySearchAugmentClaims(context, user, "email"))
                    {
                        TrySearchAugmentClaims(context, user, "upn", "email");
                    }
                }
            }

            context.LogIssuedClaims(logger);

            return Task.CompletedTask;
        }

        private bool TrySearchAugmentClaims(ProfileDataRequestContext context, E2EUser user, string ClaimName, string destinationClaimName = null)
        {
            try
            {
                var foundClaim = user.Claims.FirstOrDefault(f => f.Type.Equals(ClaimName, System.StringComparison.CurrentCultureIgnoreCase));
                if (foundClaim != null)
                {
                    context.IssuedClaims.Add(string.IsNullOrEmpty(destinationClaimName) ? foundClaim : new System.Security.Claims.Claim(destinationClaimName, foundClaim.Value));
                    return true;
                }
            }
            catch (ArgumentNullException ex)
            {
                LogHelper.Log(LogEntryType.Error, $"Failed to retrieve claim {ClaimName}", new[] { ex.Message, ex.StackTrace }, httpContextAccessor.HttpContext);
            }
            return false;
        }

        /// <summary>
        /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
        /// (e.g. during token issuance or validation).
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public virtual Task IsActiveAsync(IsActiveContext context)
        {
            LogHelper.Log(LogEntryType.Debug, $"IsActive called from: {context.Caller}", new[] { context.Subject.GetSubjectId() }, httpContextAccessor.HttpContext);

            var user = users.FindBySubjectId(context.Subject.GetSubjectId());
            context.IsActive = user?.IsActive == true;

            return Task.CompletedTask;
        }
    }
}
