using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Request
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [StringLength(50, ErrorMessage = "Email must be at most 50 characters.")]
        public string Email { get; set; }
    }
}
