using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using IdentityServerTester.Helpers;
using IdentityServerTester.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace IdentityServerTester.Extensions
{
    [ExcludeFromCodeCoverage]
    public class AzureKeyVaultHelper : IKeyVaultHelper
    {
        private readonly string vault;
        private readonly string clientId;
        private readonly string clientSecret;

        public AzureKeyVaultHelper(IAppSettingEntity appSettings)
        {
            if (appSettings == null)
            {
                throw new ArgumentException("Configuration is missing Application Settings", nameof(appSettings));
            }

            vault = appSettings.AzureKeyVault?.Vault;
            clientId = appSettings.AzureKeyVault?.ClientId;
            clientSecret = appSettings.AzureKeyVault?.ClientSecret;
        }

        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Get exceptions would require rethrow")]
        public async Task<string> GetSecretAsync(string secretName)
        {
            try
            {
                var secret = await GetKeyVaultClient().GetSecretAsync(vault, secretName);

                return secret.Value;
            }
            catch (Exception ex)
            {
                LogHelper.Log(new LogEntry { Type = LogEntryType.Error, Operation = "GetKeyVaultClient", OperationProperties = new[] { ex.Message } });
                return null;
            }
        }

        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Set exceptions would require rethrow")]
        public async Task SetSecretAsync(string secretName, string secretValue)
        {
            try
            {
                await GetKeyVaultClient().SetSecretAsync(vault, secretName, secretValue);
            }
            catch (Exception ex)
            {
                LogHelper.Log(new LogEntry { Type = LogEntryType.Error, Operation = "SetSecretAsync", OperationProperties = new[] { ex.Message } });
            }
        }

        public static KeyVaultClient GetKeyVaultClientFromManagedIdentity()
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            return new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
        }

        private KeyVaultClient GetKeyVaultClient()
        {
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessTokenAsync));
            }

            return GetKeyVaultClientFromManagedIdentity();
        }

        private async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var clientCredential = new ClientCredential(clientId, clientSecret);
            var authenticationContext = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await authenticationContext.AcquireTokenAsync(resource, clientCredential);

            return result.AccessToken;
        }
    }
}
