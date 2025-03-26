using Ecos.Infrastructure.Services.Azure.Models;

namespace Ecos.Infrastructure.Services.Azure.Interfaces;

public interface ILogTableService
{
    Task<LogEventModel?> GetQueueRowAsync(string rowKey, string partitionKey);
    Task<LogEventModel> AddRowAsync(LogEventModel model);
    Task<LogEventModel> AddOrUpdateRowAsync(LogEventModel model);
    Task DeleteRowAsync(LogEventModel model);
}
