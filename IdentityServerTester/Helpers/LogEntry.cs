using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerTester.Helpers
{
    public class LogEntry
    {
        public LogEntryType Type { get; set; }
        public string Role { get; set; }
        public string Operation { get; set; }
        public string[] OperationProperties { get; set; }
    }
}
