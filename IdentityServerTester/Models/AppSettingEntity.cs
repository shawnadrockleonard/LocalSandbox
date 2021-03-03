using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerTester.Models
{
    public class AppSettingEntity : IAppSettingEntity
    {

        public virtual AzureKeyValueEntity AzureKeyVault { get; set; }

        public string AzureStorageAccessKey { get; set; }

        public virtual ConnectionStringEntity ConnectionStrings { get; set; }

     
    }
}
