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
        public string Type => "folder";

        public List<FolderPathItem> path { get; set; }

        public FolderResponse(Guid id, string name, List<FileResponse> files, List<FolderResponse> subFolders, List<FolderPathItem> Path)
        {
            Id = id;
            Name = name;
            Files = files ?? new List<FileResponse>();
            SubFolders = subFolders ?? new List<FolderResponse>();
            path = Path;
        }
    }
}
