using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Response
{
    public class FolderResponse
    {
        public Guid Id { get; set; }
        public string Name { get; set; }

        public string? CreatedBy { get; set; }       
        public DateTime CreatedAt { get; set; }
        public string SizeFormatted { get; set; }
        public int TotalContents => (Files?.Count ?? 0) + (SubFolders?.Count ?? 0); 

        public List<FileResponse> Files { get; set; }
        public List<FolderResponse> SubFolders { get; set; }
        public string Type => "folder";

        public List<FolderPathItem> path { get; set; }

        public FolderResponse(
         Guid id,
         string name,
         List<FileResponse> files,
         List<FolderResponse> subFolders,
         List<FolderPathItem> path,
         string? createdBy,
         DateTime createdAt,
         string totalSizeFormatted
     )
        {
            Id = id;
            Name = name;
            Files = files ?? new List<FileResponse>();
            SubFolders = subFolders ?? new List<FolderResponse>();
            this.path = path ?? new List<FolderPathItem>();
            CreatedBy = createdBy;
            CreatedAt = createdAt;
            SizeFormatted = totalSizeFormatted;
        }
    }
}
