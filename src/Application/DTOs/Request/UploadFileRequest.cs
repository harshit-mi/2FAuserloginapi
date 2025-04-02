using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Ecos.Application.DTOs.Request
{
    public class UploadFileRequest
    {
        public List<IFormFile> Files { get; set; } = new();
        public Guid FolderId { get; set; }
    }
}
