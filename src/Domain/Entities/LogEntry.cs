using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Ecos.Domain.Entities
{
    public class LogEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid(); 
        public string Action { get; set; } 
        public TrackedEntity Entity { get; set; }
        public Guid? EntityId { get; set; } 
        public JsonDocument? OldValue { get; set; }
        public JsonDocument? NewValue { get; set; } 
        public string PerformedBy { get; set; } 
        public DateTime Timestamp { get; set; } 
        public string IPAddress { get; set; }
        public string UserAgent { get; set; } 
        public string? AdditionalInfo { get; set; } 
    }
}
