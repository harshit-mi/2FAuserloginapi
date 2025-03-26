using Microsoft.WindowsAzure.Storage.Table;

namespace Ecos.Infrastructure.Services.Azure.Models;

public class LogEventModel : TableEntity
{
    public string? Message { get; set; }
    public Guid? UserID { get; set; }
    public string? UpdatedInfo { get; set; }
    public string? OriginalInfo { get; set; }
    public enum FuncionType
    {
        Consult,
        Add,
        Update,
        Delete,
        Print,
        Export,
        Download,
        Upload
    }
    public enum Funcionality
    {
        
    }

    public string? Level { get; set; }
    public string? LogEventId { get; set; }
    public DateTime TimeStamp { get; set; }
    public string? PartitionKey { get; set; }
    public string? RowKey { get; set; }
}