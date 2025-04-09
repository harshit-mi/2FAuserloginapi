using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Domain.Entities
{
    public class FileUploadRetry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid RetryKey { get; set; } = Guid.NewGuid();
        public Guid UserId { get; set; }
        public Guid FolderId { get; set; }
        public string FileName { get; set; }
        public string ContentType { get; set; }
        public long Size { get; set; }
        public byte[] FileContent { get; set; } // New
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public int RetryCount { get; set; } = 0;
        public bool IsUploaded { get; set; } = false;
        public string? Error { get; set; }
    }
}
