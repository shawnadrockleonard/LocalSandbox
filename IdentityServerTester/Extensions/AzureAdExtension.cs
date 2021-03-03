using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServerTester.Extensions
{
    public static class AzureAdExtension
    {
        public static void AddOpenId(this IServiceCollection services, IConfiguration Configuration)
        {
            var oidcSection = Configuration.GetSection("Authentication:oidc");
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = "oidc";
            }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
            //.AddOpenIdConnect("oidc", options =>
            //{
            //    options.Authority = HostingEnvironment.IsDevelopment() ? oidcSection["LocalAuthority"] : oidcSection["Authority"];
            //    options.RequireHttpsMetadata = true;
            //    options.ClientId = oidcSection["ClientId"];
            //    options.ClientSecret = oidcSection["ClientSecret"];
            //    options.SaveTokens = true;
            //        //options.Scope.Add("openid");
            //        //options.Scope.Add("profile");
            //        //options.Scope.Add("email");
            //        //options.Scope.Add("secureapi");
            //        options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
            //    {
            //        OnTokenValidated = async context =>
            //        {


            //            if (context.Principal.Identity is ClaimsIdentity identity)
            //            {
            //                if (userInfoResponse?.IsError == true)
            //                {
            //                    var nameIdentity = accessToken.Claims.FirstOrDefault(fd => fd.Type.Equals("email", StringComparison.OrdinalIgnoreCase));
            //                    if (nameIdentity != null)
            //                    {
            //                        identity.AddClaim(new Claim("name", nameIdentity.Value));
            //                    }
            //                    var emailIdentity = accessToken.Claims.FirstOrDefault(fd => fd.Type.Equals("email", StringComparison.OrdinalIgnoreCase));
            //                    if (emailIdentity != null)
            //                    {
            //                        identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", emailIdentity.Value));
            //                        identity.AddClaim(new Claim("Email", emailIdentity.Value));
            //                    }
            //                }
            //                else
            //                {
            //                    var email = userInfoResponse.Claims?.FirstOrDefault(s => s.Type.Equals("name", StringComparison.OrdinalIgnoreCase))?.Value;
            //                    identity.AddClaim(new Claim("name", userInfoResponse.Claims?.FirstOrDefault(s => s.Type.Equals("name", StringComparison.OrdinalIgnoreCase))?.Value));
            //                    identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", email));
            //                    identity.AddClaim(new Claim("Email", email));
            //                }
            //            }

            //            context.Success();
            //        }
            //    };
            //})
            ;

        }
    }
}
