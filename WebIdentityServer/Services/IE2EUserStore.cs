using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace WebIdentityServer.Services
{
    [SuppressMessage("Minor Code Smell", "S3956: Refactor this method to use a generic collection for inheritance.", Justification = "User store for e2e.")]
    public interface IE2EUserStore
    {
        E2EUser AutoProvisionUser(string provider, string userId, List<Claim> claims);
        E2EUser FindByExternalProvider(string provider, string userId);
        E2EUser FindBySubjectId(string subjectId);
        E2EUser FindByUsername(string username);
        bool ValidateCredentials(string username, string password);
    }
}
