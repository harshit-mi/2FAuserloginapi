using System.ComponentModel.DataAnnotations;

namespace Ecos.Application.DTOs.Request;

public class VerifyCodeRequest
{
    [Required]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    [StringLength(50, ErrorMessage = "Email must be at most 50 characters.")]
    public string Email { get; set; } = null!;

    [Required]
    public string Code { get; set; } = null!;
    //public bool RememberMe { get; set; }
}