using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace Ecos.Application.Services
{
    public class LoggingService
    {
        private readonly DataContext _dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoggingService(DataContext dbContext, IHttpContextAccessor httpContextAccessor)
        {
            _dbContext = dbContext;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogAsync(string action, TrackedEntity entity, Guid? entityId, object? oldValue, object? newValue, string performedBy)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;

                var logEntry = new LogEntry
                {
                    Action = action,
                    Entity = entity,
                    EntityId = entityId,
                    OldValue = oldValue != null ? JsonDocument.Parse(JsonSerializer.Serialize(oldValue)) : null,
                    NewValue = newValue != null ? JsonDocument.Parse(JsonSerializer.Serialize(newValue)) : null,
                    PerformedBy = performedBy,
                    IPAddress = httpContext?.Connection?.RemoteIpAddress?.ToString(),
                    UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow,
                    AdditionalInfo = "N/A"
                };

                await _dbContext.Logs.AddAsync(logEntry);
                await _dbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Logging failed: {ex.Message}");
                await SaveLogFailureAsync(action, entity, performedBy, ex.Message);
            }
        }

        // Handle Logging Failures Separately
        private async Task SaveLogFailureAsync(string action, TrackedEntity entity, string performedBy, string errorDetails)
        {
            try
            {
                var logFailureEntry = new LogEntry
                {
                    Action = "LOGGING_FAILURE",
                    Entity = entity,
                    NewValue = JsonDocument.Parse(JsonSerializer.Serialize(new { FailedAction = action, Error = errorDetails })),
                    PerformedBy = performedBy,
                    Timestamp = DateTime.UtcNow
                };

                await _dbContext.Logs.AddAsync(logFailureEntry);
                await _dbContext.SaveChangesAsync();
            }
            catch
            {
                Console.WriteLine("Critical failure: Unable to log logging failure.");
            }
        }

        public async Task LogErrorAsync(string errorMessage, string stackTrace, string performedBy)
        {
            await LogAsync("ERROR", TrackedEntity.System, null, null,
                new { ErrorMessage = errorMessage, StackTrace = stackTrace }, performedBy);
        }

        public async Task<IEnumerable<LogEntry>> GetLogsAsync(TrackedEntity? entity = null, Guid? id = null)
        {
            var query = _dbContext.Logs.AsQueryable();

            if (entity.HasValue)
            {
                query = query.Where(log => log.Entity == entity.Value);
            }

            if (id.HasValue)
            {
                query = query.Where(log => log.EntityId == id);
            }

            return await query.ToListAsync();
        }
    }
}
