namespace WebIdentityServer.Helpers
{
    public class LogEntry
    {
        public LogEntryType Type { get; set; }
        public string Role { get; set; }
        public string Operation { get; set; }
        public string[] OperationProperties { get; set; }
    }
}
