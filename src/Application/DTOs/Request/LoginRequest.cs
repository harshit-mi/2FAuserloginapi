using System.ComponentModel.DataAnnotations;

namespace Ecos.Application.DTOs.Request
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        public string Email { get; set; } = null!;

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; } = null!;
        //public string? TwoFactorRecoveryCode { get; set; }
        //public string? TwoFactorCode { get; set; }
    }
}
