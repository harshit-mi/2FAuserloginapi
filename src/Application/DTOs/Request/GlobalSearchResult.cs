using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Request
{
    public class GlobalSearchResult
    {
        public List<SearchItem> Files { get; set; } = new();
        public List<SearchItem> Folders { get; set; } = new();
    }
}
