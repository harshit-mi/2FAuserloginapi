using System.ComponentModel.DataAnnotations;

namespace Ecos.Application.DTOs.Request
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [StringLength(50, ErrorMessage = "Email must be at most 50 characters.")]
        public string Email { get; set; } = null!;

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(20, ErrorMessage = "Password must be at most 20 characters.")]
        public string Password { get; set; } = null!;
        //public string? TwoFactorRecoveryCode { get; set; }
        //public string? TwoFactorCode { get; set; }
    }
}
