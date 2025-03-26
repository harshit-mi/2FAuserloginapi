using System.Net;
using Ecos.Api.Controllers.Base;
using Ecos.Application.DTOs.Request;
using Ecos.Common.Utils;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity.Data;
using Ecos.Infrastructure.Emails.Templates.Models;

namespace Ecos.Api.Controllers;

[Route("[controller]")]
public class AuthController : ApiControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthLogTableService _authLogTableService;
    private readonly IEmailCommunicationService _emailService;

    public AuthController(
        UserManager<User> userManager, 
        SignInManager<User> signInManager,
        ILogger<AuthController> logger, 
        IAuthLogTableService authLogService,
        IEmailCommunicationService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _authLogTableService = authLogService;
        _emailService = emailService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        string? userAgent = Request.Headers.UserAgent.ToString();

        User? user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Login attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress, userAgent);
            return BadRequest(new { message = "Invalid email or password" });
        }
        
        //var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
        //if (!result.Succeeded)
        //{
        //    string status = result.IsLockedOut ? "LockedOut" : "InvalidPassword";
        //    _logger.LogWarning("Login attempt failed for email: {Email}, Status: {Status}", request.Email, status);
        //    await _authLogTableService.LogLoginAttemptAsync(request.Email, status, ipAddress, userAgent);
        //    return BadRequest(new { message = "Invalid email or password" });
        //}

        string code = Generator.VerifyCode();
        
        // Store the code with user
        await _userManager.SetAuthenticationTokenAsync(
            user, 
            "LoginProvider", 
            "VerificationCode", 
            code);
        
        // Set expiration token
        await _userManager.SetAuthenticationTokenAsync(
            user,
            "LoginProvider",
            "VerificationCodeExpires",
            DateTime.UtcNow.AddMinutes(15).ToString("o"));


        // Log verification code generation
        await _authLogTableService.LogVerificationCodeAsync(request.Email, ipAddress);
        VerificationCodeViewModel obje = new VerificationCodeViewModel();
        obje.Code = code;
        // Send email with code
        // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
        string emailBody = await _emailService.RenderViewToStringAsync("C:/MI/Projects/Ecos/ecos-api/src/Infrastructure/Emails/Templates/VerificationCode.cshtml", obje);
        await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);

        _logger.LogInformation("Login attempt for {Email} successfully", request.Email);
        return Ok(new { message = "Verification code sent to your email" });
    }

    

    [HttpPost("verify")]
    public async Task<IActionResult> VerifyCode([FromBody] VerifyCodeRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Verification attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress);
            return BadRequest(new { message = "Invalid verification attempt" });
        }
        
        // Get stored code and expiration
        var storedCode = await _userManager.GetAuthenticationTokenAsync(
            user, 
            "LoginProvider", 
            "VerificationCode");
        
        var expirationStr = await _userManager.GetAuthenticationTokenAsync(
            user,
            "LoginProvider",
            "VerificationCodeExpires");
        
        if (string.IsNullOrEmpty(storedCode) || string.IsNullOrEmpty(expirationStr))
        {
            _logger.LogWarning("No verification code found for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "NoVerificationCode", ipAddress);
            return BadRequest(new { message = "No verification code found" });
        }
        
        // Check expiration
        if (!DateTime.TryParse(expirationStr, out var expiration) || expiration < DateTime.UtcNow)
        {
            _logger.LogWarning("Verification code expired for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ExpiredCode", ipAddress);
            return BadRequest(new { message = "Verification code has expired" });
        }
        
        // Verify code
        if (request.Code != storedCode)
        {
            _logger.LogWarning("Invalid verification code for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "InvalidCode", ipAddress);
            return BadRequest(new { message = "Invalid verification code" });
        }
        
        // Clear used tokens
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");

        // Sign in user
        await _signInManager.SignInAsync(user, isPersistent: request.RememberMe);

        // Log successful login
        await _authLogTableService.LogLoginAttemptAsync(request.Email, "Success", ipAddress);
        
        _logger.LogInformation("User {Email} logged in successfully", request.Email);
        return Ok(new { message = "Login successful" });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        string? userAgent = Request.Headers.UserAgent.ToString();
        
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Password reset attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ForgotPassword_UserNotFound", ipAddress, userAgent);
            // Return OK to prevent email enumeration attacks
            return Ok(new { message = "If your email exists in our system, you will receive a password reset link." });
        }
        
        // Generate reset token
        string token = await _userManager.GeneratePasswordResetTokenAsync(user);
        
        // Create reset URL with token - typically this would be a frontend URL
        string encodedToken = WebUtility.UrlEncode(token);
        string resetUrl = $"{Request.Scheme}://{Request.Host}/reset-password?email={request.Email}&token={encodedToken}";

        // Send email with reset link
        string emailBody = await _emailService.RenderViewToStringAsync("EmailTemplates/ResetPassword", resetUrl);
        await _emailService.SendEmailAsync(user.Email!, "Reset Your Password", emailBody);

        // Log password reset request
        await _authLogTableService.LogLoginAttemptAsync(request.Email, "ForgotPassword_TokenSent", ipAddress, userAgent);

        _logger.LogInformation("Password reset email sent for {Email}", request.Email);
    
        return Ok(new { message = "If your email exists in our system, you will receive a password reset link." });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
    
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Password reset attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ResetPassword_UserNotFound", ipAddress);
            return BadRequest(new { message = "Invalid reset attempt." });
        }
        
        var result = await _userManager.ResetPasswordAsync(user, request.ResetCode, request.NewPassword);

        if (!result.Succeeded)
        {
            string errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogWarning("Password reset failed for {Email}: {Errors}", request.Email, errors);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ResetPassword_Failed", ipAddress);
            return BadRequest(new { message = "Password reset failed.", errors });
        }
        
        // Log password reset success
        await _authLogTableService.LogPasswordResetRequestAsync(request.Email, ipAddress);
    
        _logger.LogInformation("Password reset successful for {Email}", request.Email);
    
        return Ok(new { message = "Your password has been reset successfully." });
    }
    
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { message = "Logged out successfully" });
    }

    [HttpPost("resend-code")]
    public async Task<IActionResult> ResendCode([FromBody] VerifyCodeRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Resend code attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress);
            return BadRequest(new { message = "Invalid resend attempt" });
        }

        // Get expiration
        var expirationStr = await _userManager.GetAuthenticationTokenAsync(
            user,
            "LoginProvider",
            "VerificationCodeExpires");

        if (!string.IsNullOrEmpty(expirationStr))
        {
            if (DateTime.TryParse(expirationStr, out var expiration) ||(DateTime.UtcNow - expiration).TotalMinutes < 1)
            {
                return BadRequest(new { message = "Please wait 1 minute before requesting a new code." });
            }
            else
            {
                // Clear used tokens
                await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
                await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");

                string code = Generator.VerifyCode();

                // Store the code with user
                await _userManager.SetAuthenticationTokenAsync(
                    user,
                    "LoginProvider",
                    "VerificationCode",
                    code);

                // Set expiration token
                await _userManager.SetAuthenticationTokenAsync(
                    user,
                    "LoginProvider",
                    "VerificationCodeExpires",
                    DateTime.UtcNow.AddMinutes(15).ToString("o"));

                // Log verification code generation
                await _authLogTableService.LogVerificationCodeAsync(request.Email, ipAddress);

                // Send email with code
                // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
                string emailBody = await _emailService.RenderViewToStringAsync("EmailTemplates/VerificationCode", code);
                await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);
            }
        }
        else
        {
            string code = Generator.VerifyCode();

            // Store the code with user
            await _userManager.SetAuthenticationTokenAsync(
                user,
                "LoginProvider",
                "VerificationCode",
                code);

            // Set expiration token
            await _userManager.SetAuthenticationTokenAsync(
                user,
                "LoginProvider",
                "VerificationCodeExpires",
                DateTime.UtcNow.AddMinutes(15).ToString("o"));

            // Log verification code generation
            await _authLogTableService.LogVerificationCodeAsync(request.Email, ipAddress);

            // Send email with code
            // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
            string emailBody = await _emailService.RenderViewToStringAsync("EmailTemplates/VerificationCode", code);
            await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);
        }

        _logger.LogInformation("User {Email} logged in successfully", request.Email);
        return Ok(new { message = "Login successful" });
    }
    // TODO: Implement get user details, like name, email, 

    // TODO: Implement update user details, like name, email, etc.
}