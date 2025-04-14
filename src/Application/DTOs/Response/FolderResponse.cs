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
        public List<FileResponse> Files { get; set; }
        public List<FolderResponse> SubFolders { get; set; }
        public List<FolderPathItem> path { get; set; }
        public string? CreatedBy { get; set; }
        public DateTime CreatedAt { get; set; }
        public string SizeFormatted { get; set; }
        public int TotalContents { get; set; }
        public string Type => "folder";

        public FolderResponse(Guid id, string name, List<FileResponse> files, List<FolderResponse> subFolders,
            List<FolderPathItem> Path, string? createdBy, DateTime createdAt, string sizeFormatted, int totalContents)
        {
            Id = id;
            Name = name;
            Files = files;
            SubFolders = subFolders;
            path = Path;
            CreatedBy = createdBy;
            CreatedAt = createdAt;
            SizeFormatted = sizeFormatted;
            TotalContents = totalContents;
        }
    }
}
