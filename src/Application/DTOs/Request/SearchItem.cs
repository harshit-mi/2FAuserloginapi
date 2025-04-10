using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Ecos.Application.DTOs.Response;

namespace Ecos.Application.DTOs.Request
{
    public class SearchItem
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // "File", "Folder", etc.
        public DateTime CreatedAt { get; set; }

       
        public List<FolderPathItem> Path { get; set; } = new();

        public string SizeFormatted { get; set; } = string.Empty;

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Extension => Type == "File"
            ? System.IO.Path.GetExtension(Name)?.TrimStart('.').ToLowerInvariant()
            : null;

        [JsonIgnore]
        public List<SearchItem>? Files { get; set; }

        [JsonIgnore]
        public List<SearchItem>? SubFolders { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? TotalContents => Type == "Folder"
            ? (Files?.Count ?? 0) + (SubFolders?.Count ?? 0)
            : null;
    }
}
