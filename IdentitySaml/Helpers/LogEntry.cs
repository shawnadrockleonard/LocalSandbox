using IdentityServerTester.Models;
using System.Collections.Generic;

namespace IdentityServerTester.Helpers
{
    public class LogEntry
    {
        public LogEntryType Type { get; set; }
        public string Role { get; set; }
        public string Operation { get; set; }
        public OperationStatusType OperationStatusType { get; set; }
        public IEnumerable<string> OperationProperties { get; set; }
    }
}
