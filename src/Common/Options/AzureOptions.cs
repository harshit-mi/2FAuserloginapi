namespace Ecos.Common.Options;

public class AzureStorageAccountOptions
{
    public const string SectionName = "Azure:StorageAccount";
    public string StorageKey { get; set; } = null!;
    public string AccountStoragePath { get; set; } = null!;
    public string ConnectionString { get; set; } = null!;
}

public class AzureEmailCommunicationOptions
{
    public const string SectionName = "Azure:EmailCommunication";
    public string SenderAddress { get; set; } = null!;
    public string ConnectionString { get; set; } = null!;
}