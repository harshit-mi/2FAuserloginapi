using Microsoft.WindowsAzure.Storage.Table;

namespace Ecos.Infrastructure.Services.Azure.Models;

public class AuthLogEventModel : TableEntity
{
    public string Email { get; set; } = null!;
    public string Action { get; set; } = null!;
    public string Status { get; set; } = null!;
    public string? IPAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
}