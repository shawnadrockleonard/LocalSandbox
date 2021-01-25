using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using IdentityServer4;
using IdentityServer4.Models;

namespace WebIdentityServer.Services
{
    [SuppressMessage("Minor Code Smell", "S138: The method has too many lines.", Justification = "constant class")]
    [SuppressMessage("Minor Code Smell", "S1200: Split this class into smaller and more specialized ones to reduce its dependencies.", Justification = "constant class")]
    public static class Config
    {
        public const string SecureApiId = "secureapi";

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new[]
            {
                new ApiResource(SecureApiId, "CoolBridge Apis")
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            var grants = new List<string>();
            grants.AddRange(GrantTypes.ClientCredentials);
            grants.AddRange(GrantTypes.Implicit);


            return new[]
            {
                // client credentials flow client
                new Client
                {
                    ClientId = "client",
                    ClientName = "Client Credentials Client",

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = {new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256())},

                    AllowedScopes = { SecureApiId }
                },

                // MVC client using hybrid flow
                new Client
                {
                    ClientId = "coolbridge",
                    ClientName = "Test Client",
                    RequireConsent = false,
                    AllowedGrantTypes = grants.ToList(),
                    ClientSecrets = {new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256())},

                    RedirectUris = {
                        "https://localhost:44358/signin-oidc",
                        "https://localhost:44358",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us/signin-oidc",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us"
                    },
                    FrontChannelLogoutUri = "https://localhost:44358/signout-oidc",
                    PostLogoutRedirectUris = {
                        "https://localhost:44358/signout-callback-oidc",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us/signout-callback-oidc"
                    },

                    AllowOfflineAccess = true,
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        SecureApiId
                    }
                },

                // SPA client using implicit flow
                new Client
                {
                    ClientId = "angular_spa",
                    ClientName = "CoolBridge Angular",
                    RequireConsent = false,
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowAccessTokensViaBrowser = true,
                    AlwaysSendClientClaims = true,
                    AlwaysIncludeUserClaimsInIdToken = true,
                    RequirePkce = true,
                    RequireClientSecret = false,
                    RedirectUris =
                    {
                        "http://localhost:62114",
                        "http://localhost:62114/splash",
                        "http://localhost:4200",
                        "http://localhost:4200/splash",
                        "http://localhost:4200/auth-callback",
                        "http://localhost:4200/silent-refresh.html",
                        "https://localhost:44315",
                        "https://localhost:44315/splash",
                        "https://localhost:44385",
                        "https://localhost:44385/splash",
                        "https://localhost:44358/",
                        "https://coolbridge.azurewebsites.us",
                        "https://coolbridge.azurewebsites.us/splash",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us/splash",
                        "https://appserv-coolbridge-qa.devardc.local",
                        "https://appserv-coolbridge-qa.devardc.local/splash",
                        "https://appserv-coolbridge-prod.devardc.local",
                        "https://appserv-coolbridge-prod.devardc.local/splash"
                    },
                    PostLogoutRedirectUris = {"http://localhost:62114/"},
                    AllowedCorsOrigins = new List<string>
                    {
                        "http://localhost:4200",
                        "http://localhost:62114",
                        "https://localhost:44315",
                        "https://localhost:44385",
                        "https://appserv-coolbridge.ase-coolbridge-test.p.azurewebsites.us",
                        "https://appserv-coolbridge-qa.devardc.local",
                        "https://appserv-coolbridge-prod.devardc.local"
                    },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        SecureApiId
                    }
                }
            };
        }
    }
}
