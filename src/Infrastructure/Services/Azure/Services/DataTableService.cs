using Ecos.Common.Options;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

namespace Ecos.Infrastructure.Services.Azure.Services;

public abstract class DataTableService<T> : IDataTableService<T> where T : ITableEntity, new()
{
    private readonly AzureStorageAccountOptions _azureStorageAccountOptions;
    private readonly ILogger<DataTableService<T>> _logger;

    protected DataTableService(IOptions<AzureStorageAccountOptions> options, ILogger<DataTableService<T>> logger)
    {
        _azureStorageAccountOptions = options.Value;
        _logger = logger;
    }

    public async Task<List<T>> GetAllRowsAsync()
    {
        CloudTable cloudTable = await CreateTableAsync();
        TableQuery<T> query = new();
        List<T> results = [];
        TableContinuationToken token = null;

        do
        {
            TableQuerySegment<T> segment = await cloudTable.ExecuteQuerySegmentedAsync(query, token);
            results.AddRange(segment.Results);
            token = segment.ContinuationToken;
        } while (token != null);

        return results;
    }

    public async Task<T> GetQueueRowAsync(string rowKey, string? partitionKey = null)
    {
        partitionKey = string.IsNullOrWhiteSpace(partitionKey) ? GetPartitionKey() : partitionKey;

        _logger.LogInformation("Retrieving tableStorage row {RowKey}:{PartitionKey}", rowKey, partitionKey);

        TableOperation? operation = TableOperation.Retrieve<T>(partitionKey, rowKey);

        CloudTable cloudTable = await CreateTableAsync();
        TableResult? result = await cloudTable.ExecuteAsync(operation);

        string logMessage = result.Result == null
            ? $"Not Found tableStorage row {rowKey}:{partitionKey}..."
            : $"Retrieved tableStorage row {rowKey}:{partitionKey} successfully";

        _logger.LogInformation(logMessage);

        return (T)result.Result!;
    }

    public async Task<T> AddOrUpdateRowAsync(T model)
    {
        return await InternalAction(model, Func, "Upserting", "upserted");

        TableOperation Func(T item)
        {
            return TableOperation.InsertOrMerge(item);
        }
    }

    public async Task<T> AddRowAsync(T model)
    {
        return await InternalAction(model, Func, "Creating", "created");

        TableOperation Func(T item)
        {
            return TableOperation.Insert(item);
        }
    }

    public async Task DeleteRowAsync(T model)
    {
        await InternalAction(model, Func, "Deleting", "deleted");
        return;

        TableOperation Func(T item)
        {
            item.ETag ??= "*";
            return TableOperation.Delete(item);
        }
    }

    protected abstract string GetTableName();

    protected abstract string GetPartitionKey();

    private async Task<T> InternalAction(T model, Func<T, TableOperation> func, string executingLog, string executedLog)
    {
        _logger.LogInformation("{ExecutingLog} DataTable Row {Model} of table {TableName}",
            executingLog, ToString(model), GetTableName());

        if (string.IsNullOrWhiteSpace(model.PartitionKey))
        {
            model.PartitionKey = GetPartitionKey();
        }

        TableOperation? operation = func(model);
        CloudTable cloudTable = await CreateTableAsync();
        TableResult tableResult = await cloudTable.ExecuteAsync(operation);

        _logger.LogInformation("DataTable Row {Model} {ExecutedLog} successfully", ToString(model), executedLog);

        return (T)tableResult.Result;
    }

    public async Task<CloudTable> CreateTableAsync()
    {
        string tableName = GetTableName();
        CloudStorageAccount storageAccount = CloudStorageAccount.Parse(_azureStorageAccountOptions.ConnectionString);
        CloudTableClient? tableClient = storageAccount.CreateCloudTableClient();
        CloudTable? table = tableClient.GetTableReference(tableName);

        try
        {
            if (await table.CreateIfNotExistsAsync())
            {
                _logger.LogInformation("Created Table named: {TableName}", tableName);
            }
        }
        catch (FormatException)
        {
            _logger.LogError(
                "Invalid storage account information provided. Please confirm the AccountName and AccountKey are valid in the app.config file - then restart the application");
            throw;
        }
        catch (ArgumentException)
        {
            _logger.LogError(
                "Invalid storage account information provided. Please confirm the AccountName and AccountKey are valid in the app.config file - then restart the sample");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error on get table {TableName}", tableName);
            throw;
        }

        return table;
    }

    private static string ToString(T model)
    {
        return $"[{model} - Timestamp={model.Timestamp}, PartitionKey={model.PartitionKey}, RowKey={model.RowKey}]";
    }
}