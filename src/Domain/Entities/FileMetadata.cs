using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Domain.Entities
{
    public class FileMetadata
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long Size { get; set; }
        public string BlobStorageUrl { get; set; } = string.Empty;
        public Guid FolderId { get; set; }
        public Folder Folder { get; set; } = null!;

        public Guid UserId { get; set; }
        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    }
}
