using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Response
{
    public class FileResponse
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Url { get; set; }

        public string SizeFormatted { get; set; } = string.Empty;
        public string? UploadedBy { get; set; }
        public DateTime UploadedAt { get; set; }

        public string Type => "file";

        public string Extension => Path.GetExtension(Name)?.ToLowerInvariant();

        public List<FolderPathItem> path { get; set; }

        public FileResponse(
       Guid id,
       string name,
       string url,
       List<FolderPathItem> path,
       string sizeFormatted,
       string? uploadedBy,
       DateTime uploadedAt)
        {
            Id = id;
            Name = name;
            Url = url;
            this.path = path ?? new List<FolderPathItem>();
            SizeFormatted = sizeFormatted;
            UploadedBy = uploadedBy;
            UploadedAt = uploadedAt;
        }
    }
}
