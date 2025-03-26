using Ecos.Common.Options;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Ecos.Infrastructure.Services.Azure.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ecos.Infrastructure.Services.Azure.Services;

public class AuthLogTableService : DataTableService<AuthLogEventModel>, IAuthLogTableService
{
    public AuthLogTableService(
        IOptions<AzureStorageAccountOptions> options,
        ILogger<AuthLogTableService> logger)
        : base(options, logger)
    {
    }
    
    protected override string GetPartitionKey() => DateTime.UtcNow.ToString("yyyy-MM-dd");

    protected override string GetTableName() => AzureConstants.AuthEventControlTableName;
    
    public async Task LogLoginAttemptAsync(string email, string status, string? ipAddress = null, string? userAgent = null)
    {
        await AddRowAsync(new AuthLogEventModel
        {
            RowKey = Guid.NewGuid().ToString(),
            Email = email,
            Action = "LoginAttempt",
            Status = status,
            IPAddress = ipAddress,
            UserAgent = userAgent
        });
    }
    
    public async Task LogVerificationCodeAsync(string email, string? ipAddress = null)
    {
        await AddRowAsync(new AuthLogEventModel
        {
            RowKey = Guid.NewGuid().ToString(),
            Email = email,
            Action = "VerificationCodeGenerated",
            Status = "Pending",
            IPAddress = ipAddress,
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        });
    }
    
    public async Task LogPasswordResetRequestAsync(string email, string? ipAddress = null)
    {
        await AddRowAsync(new AuthLogEventModel
        {
            RowKey = Guid.NewGuid().ToString(),
            Email = email,
            Action = "PasswordResetRequested",
            Status = "Pending", 
            IPAddress = ipAddress,
            ExpiresAt = DateTime.UtcNow.AddHours(24)
        });
    }
}