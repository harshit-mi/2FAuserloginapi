using Microsoft.WindowsAzure.Storage.Table;

namespace Ecos.Infrastructure.Services.Azure.Interfaces;

public interface IDataTableService<T> where T : ITableEntity
{
    Task<T> AddRowAsync(T model);
    Task<T> AddOrUpdateRowAsync(T model);
    Task<T> GetQueueRowAsync(string rowKey, string? partitionKey = null);
    Task DeleteRowAsync(T model);
    Task<List<T>> GetAllRowsAsync();
}