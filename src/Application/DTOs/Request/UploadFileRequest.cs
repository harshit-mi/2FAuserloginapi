using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Ecos.Application.DTOs.Request
{
    public class UploadFileRequest
    {
        public List<FileUploadItem> Files { get; set; } = new();
        public Guid? FolderId { get; set; }
    }

    public class FileUploadItem
    {
        public Guid FileId { get; set; } // Provided by frontend
        public IFormFile File { get; set; }
    }
}
