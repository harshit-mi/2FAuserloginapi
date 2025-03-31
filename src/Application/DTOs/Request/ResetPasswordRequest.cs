﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.DTOs.Request
{
    public class ResetPasswordRequest
    {

        [Required]
        public string ResetToken { get; init; }
        [Required]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")]
        [StringLength(20, ErrorMessage = "Password must be at most 20 characters.")]
        [DefaultValue("string")]
        [RegularExpression(@"^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$",
ErrorMessage = "Password must contain at least one uppercase letter, one number, and one special character.")]
        public string NewPassword { get; init; }
        [Required]
        [Compare(nameof(NewPassword), ErrorMessage = "Confirm Password must match the new password.")]
        public string ConfirmPassword { get; init; }
    }
}
