using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Request
{
    public class TokenVerificationRequest
    {
        public string AuthToken { get; set; } = string.Empty;
    }
}
