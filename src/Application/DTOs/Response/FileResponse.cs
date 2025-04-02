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
        public string Type => "file";

        public FileResponse(Guid id, string name, string url)
        {
            Id = id;
            Name = name;
            Url = url;
        }
    }
}
