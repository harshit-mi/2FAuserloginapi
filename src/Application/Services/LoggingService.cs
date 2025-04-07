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
using Microsoft.Extensions.DependencyInjection;

namespace Ecos.Application.Services
{
    public class LoggingService : ILoggingService
    {
        //private readonly DataContext _dbContext;
        //private readonly IHttpContextAccessor _httpContextAccessor;

        //public LoggingService(DataContext dbContext, IHttpContextAccessor httpContextAccessor)
        //{
        //    _dbContext = dbContext;
        //    _httpContextAccessor = httpContextAccessor;
        //}
        private readonly DataContext _dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoggingService(IServiceScopeFactory scopeFactory, IHttpContextAccessor httpContextAccessor)
        {
            // Create scope and resolve DataContext once, for this service lifetime
            var scope = scopeFactory.CreateScope();
            _dbContext = scope.ServiceProvider.GetRequiredService<DataContext>();
            _httpContextAccessor = httpContextAccessor;
        }
        public async Task LogAsync(
            string action,
            TrackedEntity entity,
            Guid? entityId,
            object? oldValue,
            object? newValue,
            string performedBy,
            string? message = null,
            string? additionalInfo = null)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;

                var logEntry = new LogEntry
                {
                    Id = Guid.NewGuid(),
                    Action = action,
                    Entity = entity,
                    EntityId = entityId,
                    Message = message,
                    OldValue = oldValue != null ? JsonDocument.Parse(JsonSerializer.Serialize(oldValue)) : null,
                    NewValue = newValue != null ? JsonDocument.Parse(JsonSerializer.Serialize(newValue)) : null,
                    PerformedBy = performedBy,
                    IPAddress = httpContext?.Connection?.RemoteIpAddress?.ToString(),
                    UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow,
                    AdditionalInfo = additionalInfo ?? GenerateAdditionalInfo(action, entity, entityId, performedBy)
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

        private string GenerateAdditionalInfo(string action, TrackedEntity entity, Guid? entityId, string performedBy)
        {
            return $"Action '{action}' was performed on '{entity}' (ID: {entityId?.ToString() ?? "N/A"}) by '{performedBy}' at {DateTime.UtcNow:u}";
        }

        private async Task SaveLogFailureAsync(string action, TrackedEntity entity, string performedBy, string errorDetails)
        {
            try
            {
                var logFailureEntry = new LogEntry
                {
                    Id = Guid.NewGuid(),
                    Action = "LOGGING_FAILURE",
                    Entity = entity,
                    Message = $"Logging failed for action: {action}",
                    NewValue = JsonDocument.Parse(JsonSerializer.Serialize(new
                    {
                        FailedAction = action,
                        Error = errorDetails
                    })),
                    PerformedBy = performedBy,
                    Timestamp = DateTime.UtcNow,
                    AdditionalInfo = "Automatic fallback for logging failure."
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
            await LogAsync(
                action: "ERROR",
                entity: TrackedEntity.System,
                entityId: null,
                oldValue: null,
                newValue: new { ErrorMessage = errorMessage, StackTrace = stackTrace },
                performedBy: performedBy,
                message: "Unhandled exception occurred.",
                additionalInfo: $"Stack trace captured at {DateTime.UtcNow:u}"
            );
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
