using System.Collections.Generic;
using System.Security.Claims;
using IdentityModel;

namespace WebIdentityServer.Services
{
    public static class ConfigLocalUsers
    {
        public static IList<E2EUser> GetUsers(string testPassword)
            => GetUsers(testPassword, "devardc.local", 10);

        public static IList<E2EUser> GetUsers(string testPassword, string localDomain, int numOfUsers)
        {
            var testUsers = new List<E2EUser>();
            for (var idx = 1; idx <= numOfUsers; idx++)
            {
                var padId = idx.ToString().PadLeft(2, '0');
                testUsers.Add(new E2EUser
                {
                    SubjectId = $"818727{padId}",
                    Username = $"CoolBridge{padId}",
                    Password = testPassword,
                    Claims =
                    {
                        new Claim(JwtClaimTypes.Name, $"CoolBridge{padId}"),
                        new Claim(JwtClaimTypes.GivenName, "Cool"),
                        new Claim(JwtClaimTypes.FamilyName, $"Bridge{padId}"),
                        new Claim(JwtClaimTypes.Email, $"CoolBridge{padId}@{localDomain}"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean)
                    }
                });
            }
            return testUsers;
        }
    }
}
