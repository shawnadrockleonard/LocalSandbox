using System;
using System.Diagnostics.CodeAnalysis;

namespace WebIdentityServer.Models
{
    [SuppressMessage("Minor Code Smell", "S1104: Make this field private and encapsulate in 'public' property", Justification = "constant class")]
    [SuppressMessage("Minor Code Smell", "S2223:Change visibility or make 'const' or 'readonly' property", Justification = "constant class")]
    [SuppressMessage("Minor Code Smell", "S2339:Change this constant to a 'static' read-only property", Justification = "constant class")]
    public static class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = true;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static bool ShowLogoutPrompt = true;
        public static bool AutomaticRedirectAfterSignOut;

        // specify the Windows authentication scheme being used
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // if user uses windows auth, should we load the groups from windows
        public static bool IncludeWindowsGroups;
    }
}
