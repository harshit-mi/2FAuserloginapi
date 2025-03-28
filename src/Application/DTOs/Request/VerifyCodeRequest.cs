using System.ComponentModel.DataAnnotations;

namespace Ecos.Application.DTOs.Request;

public class VerifyCodeRequest
{
    public string Email { get; set; } = null!;
    public string Code { get; set; } = null!;
    //public bool RememberMe { get; set; }
}