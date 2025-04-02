using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Request
{
    public class CreateFolderRequest
    {
        public string Name { get; set; }
        public Guid? ParentFolderId { get; set; }
    }
}
