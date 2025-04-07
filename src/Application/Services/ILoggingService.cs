using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ecos.Domain.Entities;

namespace Ecos.Application.Services
{
    public interface ILoggingService
    {
        Task LogAsync(string action,TrackedEntity entity,Guid? entityId,object? oldValue,object? newValue,string performedBy,string? message = null, string? additionalInfo = null);
        Task LogErrorAsync(string errorMessage, string stackTrace, string performedBy);
        Task<IEnumerable<LogEntry>> GetLogsAsync(TrackedEntity? entity = null, Guid? id = null);
    }
}
