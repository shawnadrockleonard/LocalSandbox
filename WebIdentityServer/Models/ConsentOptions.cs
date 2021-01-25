using System.Diagnostics.CodeAnalysis;

namespace WebIdentityServer.Models
{
    [SuppressMessage("Minor Code Smell", "S1104: Make this field private and encapsulate in 'public' property", Justification = "constant class")]
    [SuppressMessage("Minor Code Smell", "S2223:Change visibility or make 'const' or 'readonly' property", Justification = "constant class")]
    [SuppressMessage("Minor Code Smell", "S2339:Change this constant to a 'static' read-only property", Justification = "constant class")]
    public static class ConsentOptions
    {
        public static bool EnableOfflineAccess = true;
    }
}
