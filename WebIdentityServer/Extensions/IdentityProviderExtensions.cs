using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using WebIdentityServer.Services;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Rsk.AspNetCore.Authentication.Saml2p;

namespace WebIdentityServer.Extensions
{
    [SuppressMessage("Minor Code Smell", "S3240: ?: Operator here.", Justification = "Do not agree with the single line approach.")]
    public static class IdentityProviderExtensions
    {
        /// <summary>
        /// Adds test users.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="defaultPassword">Default password for local user store</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddE2EProcessing(this IIdentityServerBuilder builder, IConfiguration configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            var defaultUserPassword = configuration.GetValue<string>("Authentication:DefaultPassword");
            var users = ConfigLocalUsers.GetUsers(defaultUserPassword);
            builder.Services.AddSingleton<IE2EUserStore>(new E2EUserStore(users));
            builder.AddProfileService<SamlClaimsService>();
            builder.AddResourceOwnerValidator<E2EUserResourceOwnerPasswordValidator>();
            return builder;
        }

        public static IIdentityServerBuilder AddSaml2PIdentityServerCertificates(this IIdentityServerBuilder identityServer, IConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var certificateSection = configuration.GetSection("Certificates");
            var certificateThumbprint = certificateSection["SigningCertificateThumbprint"];

            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                return identityServer;
            }

            using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certSigningCredentials = GetSigningCertificate(certificateThumbprint, certStore);

                // Identity Server configuration for SAMLP support
                return identityServer
                .AddSigningCredential(certSigningCredentials);
            }
        }

        public static IIdentityServerBuilder AddSaml2PIdentityServer(this IIdentityServerBuilder identityServer, IConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var licenseSection = configuration.GetSection("License");
            var samlLicensee = licenseSection["Licensee"];
            var sampLicenseKey = licenseSection["Key"];

            if (string.IsNullOrEmpty(samlLicensee))
            {
                return identityServer;
            }

            // Identity Server configuration for SAMLP support
            return identityServer
            .AddSamlPlugin(options =>
            {
                options.Licensee = samlLicensee;
                options.LicenseKey = sampLicenseKey;
                options.WantAuthenticationRequestsSigned = false;
            });
        }

        public static AuthenticationBuilder AddAzureAdSaml2P(this AuthenticationBuilder builder, IConfiguration configuration)
            => AddAzureAdSaml2P(builder, configuration, "saml2p", "Azure SAMLP");

        public static AuthenticationBuilder AddAzureAdSaml2P(this AuthenticationBuilder builder, IConfiguration configuration, string authenticationSchema, string displayName)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var saml2pSection = configuration.GetSection("Saml2P");
            var licenseSection = configuration.GetSection("License");
            var samlLicensee = licenseSection["Licensee"];
            var sampLicenseKey = licenseSection["Key"];
            var certificateSection = configuration.GetSection("Certificates");

            if (string.IsNullOrEmpty(samlLicensee))
            {
                return builder;
            }

            using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certSigningCredentials = GetSigningCertificate(certificateSection["SigningCertificateThumbprint"], certStore);
                var idpSigningCertificate = GetSigningCertificate(certificateSection["IdpSigningCertificateThumbprint"], certStore);

                return builder.AddSaml2p(authenticationSchema, displayName, options =>
                {
                    var samlEndpoint = saml2pSection["SignInEndpoint"];
                    var ipEntityId = saml2pSection["IpEntityId"];
                    var spEntityId = saml2pSection["SpEntityId"];

                    options.Licensee = samlLicensee;
                    options.LicenseKey = sampLicenseKey;
                    options.IdentityProviderOptions = new IdpOptions
                    {
                        EntityId = ipEntityId,
                        SigningCertificate = idpSigningCertificate,
                        SingleSignOnEndpoint = new SamlEndpoint(samlEndpoint, SamlBindingTypes.HttpRedirect),
                        SingleLogoutEndpoint = new SamlEndpoint(samlEndpoint, SamlBindingTypes.HttpRedirect),
                    };
                    options.ServiceProviderOptions = new SpOptions
                    {
                        EntityId = spEntityId,
                        MetadataPath = "/saml/metadata",
                        SignAuthenticationRequests = true,
                        SigningCertificate = certSigningCredentials
                    };
                    options.TimeComparisonTolerance = 15;
                    options.NameIdClaimType = "sub";
                    options.CallbackPath = "/signin-saml";
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.Events.OnRemoteFailure = context =>
                    {
                        context.HandleResponse();
                        if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
                        {
                            context.Response.Redirect("/");
                        }
                        else
                        {
                            context.Response.Redirect("/Home/Error?message=" + WebUtility.UrlEncode(context.Failure.Message));
                        }
                        return Task.CompletedTask;
                    };
                });
            }
        }

        public static AuthenticationBuilder AddAzureAdOpenId(this AuthenticationBuilder builder, IConfiguration configuration)
            => AddAzureAdOpenId(builder, configuration, "aad", "Azure AD");

        public static AuthenticationBuilder AddAzureAdOpenId(this AuthenticationBuilder builder, IConfiguration configuration, string authenticationSchema, string displayName)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var azureAdSection = configuration.GetSection("Saml2AzureAd");
            var azureAdOpenId = azureAdSection["Authentication"];
            var azureAdInstance = azureAdSection["Instance"];

            if (string.IsNullOrEmpty(azureAdInstance) || string.IsNullOrEmpty(azureAdOpenId))
            {
                return builder;
            }

            return builder.AddOpenIdConnect(authenticationSchema, displayName, options =>
            {
                IdentityModelEventSource.ShowPII = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.ClientId = azureAdSection["ClientId"];
                options.ClientSecret = azureAdSection["ClientSecret"];
                options.Authority = $"{azureAdSection["Instance"]}/{azureAdSection["TenantId"]}";
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role",
                };
                options.Events.OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
                    // because password reset is not supported by a "sign-up or sign-in policy"
                    if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118", StringComparison.OrdinalIgnoreCase))
                    {
                        // If the user clicked the reset password link, redirect to the reset password route
                        context.Response.Redirect("/Session/ResetPassword");
                    }
                    else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.Redirect("/");
                    }
                    else
                    {
                        context.Response.Redirect("/Home/Error?message=" + WebUtility.UrlEncode(context.Failure.Message));
                    }
                    return Task.CompletedTask;
                };
            });
        }

        public static AuthenticationBuilder AddAdfsOpenId(this AuthenticationBuilder builder, IConfiguration configuration)
            => AddAdfsOpenId(builder, configuration, "adfs", "Coolbridge ADFS");

        public static AuthenticationBuilder AddAdfsOpenId(this AuthenticationBuilder builder, IConfiguration configuration, string authenticationSchema, string displayName)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var saml2pSection = configuration.GetSection("AdfsOpenId");
            var samlOpenId = saml2pSection["Authentication"];
            var samlEndpoint = saml2pSection["Endpoint"];
            var samlClientId = saml2pSection["ClientId"];
            var samlClientSecret = saml2pSection["ClientSecret"];

            if (string.IsNullOrEmpty(samlEndpoint) || string.IsNullOrEmpty(samlOpenId))
            {
                return builder;
            }

            return builder.AddOpenIdConnect(authenticationSchema, displayName, options =>
            {
                IdentityModelEventSource.ShowPII = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.SaveTokens = true;
                options.Authority = samlEndpoint;
                options.ClientId = samlClientId;
                options.ClientSecret = samlClientSecret;
                options.ResponseType = OpenIdConnectResponseType.IdToken;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "sub",
                    RoleClaimType = "role"
                };
                options.Events.OnTicketReceived = ticketReceivedContext =>
                {
                    return Task.CompletedTask;
                };
                options.Events.OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.Redirect("/");
                    }
                    else
                    {
                        context.Response.Redirect("/Home/Error?message=" + WebUtility.UrlEncode(context.Failure.Message));
                    }
                    return Task.CompletedTask;
                };
            });
        }

        public static AuthenticationBuilder AddAdfsWsFed(this AuthenticationBuilder builder, IConfiguration configuration)
            => AddAdfsWsFed(builder, configuration, "wsfed", "Coolbridge WS-Fed");

        public static AuthenticationBuilder AddAdfsWsFed(this AuthenticationBuilder builder, IConfiguration configuration, string authenticationSchema, string displayName)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            var saml2pSection = configuration.GetSection("AdfsWsFed");
            var samlMetadataAddress = saml2pSection["MetadataAddress"];
            var samlWtrealm = saml2pSection["Wtrealm"];

            if (string.IsNullOrEmpty(samlMetadataAddress))
            {
                return builder;
            }

            return builder.AddWsFederation(authenticationSchema, displayName, options =>
            {
                // MetadataAddress represents the Active Directory instance used to authenticate users.
                options.MetadataAddress = samlMetadataAddress;
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SaveTokens = true;
                // Wtrealm is the app's identifier in the Active Directory instance.
                // For ADFS, use the relying party's identifier, its WS-Federation Passive protocol URL:
                options.Wtrealm = samlWtrealm;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role",
                };
                options.Events.OnTicketReceived = ticketReceivedContext =>
                {
                    var identity = ticketReceivedContext.Principal.Identities.First();
                    var sub = ticketReceivedContext.Principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
                    var name = identity.Claims?.FirstOrDefault(s => s.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", StringComparison.OrdinalIgnoreCase))?.Value;
                    var email = identity.Claims?.FirstOrDefault(s => s.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", StringComparison.OrdinalIgnoreCase))?.Value;

                    identity.AddClaim(new Claim("sub", sub));
                    identity.AddClaim(new Claim("name", name));
                    identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", email));
                    identity.AddClaim(new Claim("Email", email));
                    return Task.CompletedTask;
                };
                options.Events.OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.Redirect("/");
                    }
                    else
                    {
                        context.Response.Redirect("/Home/Error?message=" + WebUtility.UrlEncode(context.Failure.Message));
                    }
                    return Task.CompletedTask;
                };
            });
        }

        private static X509Certificate2 GetSigningCertificate(string certificateThumbprint, X509Store certStore)
        {
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
            var certSigningCredentials = certCollection?[0];
            return certSigningCredentials;
        }
    }
}
