using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerTester.Models
{
    public class AzureKeyValueEntity
    {
        public string Vault { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
