using Ecos.Common.Options;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Ecos.Infrastructure.Services.Azure.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ecos.Infrastructure.Services.Azure.Services;

public class AuditLogTableService : DataTableService<LogEventModel>, ILogTableService
{
    public AuditLogTableService(
        IOptions<AzureStorageAccountOptions> options,
        ILogger<AuditLogTableService> logger)
        : base(options, logger)
    {
    }

    protected override string GetPartitionKey() => Guid.NewGuid().ToString();

    protected override string GetTableName() => AzureConstants.LogEventControlTableName;
}