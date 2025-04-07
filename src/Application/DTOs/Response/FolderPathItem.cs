using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Response
{
    public class FolderPathItem
    {
        public Guid Id { get; set; }
        public string Name { get; set; }

        public FolderPathItem(Guid id, string name)
        {
            Id = id;
            Name = name;
        }
    }
}
