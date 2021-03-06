using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerTester.Models
{
    public interface IAppSettingEntity
    {
        AzureKeyValueEntity AzureKeyVault { get; set; }
        string AzureStorageAccessKey { get; set; }
        ConnectionStringEntity ConnectionStrings { get; set; }
    }
}
