using System.Net;
using Ecos.Api.Controllers.Base;
using Ecos.Application.DTOs.Request;
using Ecos.Common.Utils;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Ecos.Api.Emails.Templates.Models;
using Ecos.Application.Services;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Web;
using System.Security.Claims;

namespace Ecos.Api.Controllers;

[Route("[controller]")]
public class AuthController : ApiControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthLogTableService _authLogTableService;
    private readonly IEmailCommunicationService _emailService;
    private readonly ITokenService _tokenService;

    public AuthController(
        UserManager<User> userManager, 
        SignInManager<User> signInManager,
        ILogger<AuthController> logger, 
        IAuthLogTableService authLogService,
        IEmailCommunicationService emailService,
        ITokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _authLogTableService = authLogService;
        _emailService = emailService;
        _tokenService = tokenService;
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
            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            string status = result.IsLockedOut ? "LockedOut" : "InvalidPassword";
            _logger.LogWarning("Login attempt failed for email: {Email}, Status: {Status}", request.Email, status);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, status, ipAddress, userAgent);
            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
        }

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
        string emailBody = await _emailService.RenderViewToStringAsync("VerificationCode.cshtml", obje);
        await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);

        _logger.LogInformation("Login attempt for {Email} successfully", request.Email);
        return Ok(new { meta = new { code = 1, message = "Verification code sent to your email" } });
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
            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
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
            return BadRequest(new { meta = new { code = 0, message = "No verification code found" } });
        }
        
        // Check expiration
        if (!DateTime.TryParse(expirationStr, out var expiration) || expiration < DateTime.UtcNow)
        {
            _logger.LogWarning("Verification code expired for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ExpiredCode", ipAddress);
            return BadRequest(new { meta = new { code = 0, message = "No verification code found" } });
        }
        
        // Verify code
        if (request.Code != storedCode)
        {
            _logger.LogWarning("Invalid verification code for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "InvalidCode", ipAddress);
            return BadRequest(new { meta = new { code = 0, message = "Invalid verification code" } });
        }
        
        // Clear used tokens
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");

        string token = _tokenService.GenerateAuthToken(user.Id,user.UserName);
        var refreshToken = _tokenService.GenerateRefreshToken();
        // Store Refresh Token in Database
        await _tokenService.StoreRefreshTokenAsync(user.Id, refreshToken);
        // Sign in user
        await _signInManager.SignInAsync(user, isPersistent: true);

        // Log successful login
        await _authLogTableService.LogLoginAttemptAsync(request.Email, "Success", ipAddress);
        
        _logger.LogInformation("User {Email} logged in successfully", request.Email);
        return Ok(new { meta = new { code = 1, message = "Login successful" }, data = new { userName = user.UserName, email = user.Email, authtoken = token, RefreshToken = refreshToken } });
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
            return Ok(new { meta = new { code = 1, message = "If your email exists in our system, you will receive a password reset link." } });
        }
        // Generate reset token
        string token = await _userManager.GeneratePasswordResetTokenAsync(user);
        // Create reset URL with token - typically this would be a frontend URL
        string encodedToken = WebUtility.UrlEncode(token);
        string resetUrl = $"{Request.Scheme}://{Request.Host}/reset-password?token={HttpUtility.UrlEncode(encodedToken)}";
        ForgotPasswordViewModel obj = new ForgotPasswordViewModel();
        obj.ResetUrl = resetUrl;
        // Send email with reset link
        string emailBody = await _emailService.RenderViewToStringAsync("ForgotPassword.cshtml", obj);
        await _emailService.SendEmailAsync(user.Email!, "Reset Your Password", emailBody);
        // Log password reset request
        await _authLogTableService.LogLoginAttemptAsync(request.Email, "ForgotPassword_TokenSent", ipAddress, userAgent);
        _logger.LogInformation("Password reset email sent for {Email}", request.Email);
        return Ok(new { meta = new { code = 1, message = "If your email exists in our system, you will receive a password reset link." } });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var decodedToken = WebUtility.UrlDecode(request.ResetToken);
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var users = _userManager.Users.ToList();
        User? foundUser = null;
        foreach (var user in users)
        {
            bool isValid = await _userManager.VerifyUserTokenAsync(user,
            _userManager.Options.Tokens.PasswordResetTokenProvider,
            "ResetPassword", decodedToken);
            if (isValid)
            {
                foundUser = user;
                break; // Stop once we find a valid user
            }
        }
        if (foundUser == null)
        {
            _logger.LogWarning("Invalid password reset token.");
            return BadRequest(new { meta = new { code = 0, message = "Invalid or expired token." } });
        }
        string email = foundUser.Email;
        if (foundUser == null)
        {
            _logger.LogWarning("Password reset attempt with non-existing email: {Email}", email);
            await _authLogTableService.LogLoginAttemptAsync(email, "ResetPassword_UserNotFound", ipAddress);
            return BadRequest(new { meta = new { code = 0, message = "Invalid reset attempt." } });
        }
        var result = await _userManager.ResetPasswordAsync(foundUser, decodedToken, request.NewPassword);
        if (!result.Succeeded)
        {
            string errors1 = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogWarning("Password reset failed for {Email}: {Errors}", email, errors1);
            await _authLogTableService.LogLoginAttemptAsync(email, "ResetPassword_Failed", ipAddress);
            return BadRequest(new { meta = new { code = 0, message = "Password reset failed.", errors1 } });
        }
        // Generate Auth and Refresh Tokens
        var authToken = _tokenService.GenerateAuthToken(foundUser.Id, foundUser.UserName);
        var refreshToken = _tokenService.GenerateRefreshToken();
        // Store Refresh Token in Database
        await _tokenService.StoreRefreshTokenAsync(foundUser.Id, refreshToken);
        // Log password reset success
        await _authLogTableService.LogPasswordResetRequestAsync(email, ipAddress);
        _logger.LogInformation("Password reset successful for {Email}", email);
        return Ok(new { meta = new { code = 1, message = "Your password has been reset successfully." }, data = new { userName = foundUser.UserName, email = foundUser.Email, authtoken = authToken, RefreshToken = refreshToken } });
    }
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(new { meta = new { code = 0, message = "Invalid user session" } });
        }
        var authToken = Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        if (string.IsNullOrEmpty(authToken))
        {
            return BadRequest(new { meta = new { code = 0, message = "Token is missing" } });
        }
        // Store the token in a blacklist
        await _tokenService.BlacklistTokenAsync(authToken, userId);
        // Issue an expired token
        var expiredToken = _tokenService.GenerateExpiredToken(userId);
        // Revoke the refresh token
        await _tokenService.RevokeRefreshTokenAsync(userId);
        // Sign out user (for Identity-based authentication)
        await _signInManager.SignOutAsync();
        return Ok(new { meta = new { code = 1, message = "Logged out successfully" } });
    }

    [HttpPost("resend-code")]
    public async Task<IActionResult> ResendCode([FromBody] ResendCodeRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Resend code attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress);
            return BadRequest(new { meta = new { code = 0, message = "Invalid resend attempt" } });
        }
        // Get expiration
        var expirationStr = await _userManager.GetAuthenticationTokenAsync(
        user,
        "LoginProvider",
        "VerificationCodeExpires");
        if (!string.IsNullOrEmpty(expirationStr))
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
            VerificationCodeViewModel obje = new VerificationCodeViewModel();
            obje.Code = code;
            // Send email with code
            // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
            string emailBody = await _emailService.RenderViewToStringAsync("VerificationCode.cshtml", obje);
           
            await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);
            
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
            VerificationCodeViewModel obje = new VerificationCodeViewModel();
            obje.Code = code;
            // Send email with code
            // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
            string emailBody = await _emailService.RenderViewToStringAsync("VerificationCode.cshtml", obje);
            // Send email with code
            // TODO USE THE CORRECT TEMPLATE AND MODEL -> Infrastructure/Emails/Templates/VerificationCode.cshtml
            //string emailBody = await _emailService.RenderViewToStringAsync("EmailTemplates/VerificationCode", code);
            await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);
        }
        //_logger.LogInformation("User {Email} logged in successfully", request.Email);
        return Ok(new { meta = new { code = 1, message = "Verification code sent to your email" } });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        // Extract token from the "Authorization" header
        var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return Unauthorized(new { meta = new { code = 0, message = "Authorization header is missing or invalid." } });
        }
        var authToken = authHeader.Substring("Bearer ".Length).Trim(); // Extract token value
        var (newAuthToken, newRefreshToken) = await _tokenService.RefreshAuthTokenAsync(authToken, request.RefreshToken);
        if (newAuthToken == null || newRefreshToken == null)
        {
            return Unauthorized(new { meta = new { code = 0, message = "Invalid refresh token or expired session." } });
        }
        return Ok(new
        {
            meta = new { code = 1, message = "Token refreshed successfully." },
            data = new { authToken = newAuthToken, refreshToken = newRefreshToken }
        });
    }
    [HttpPost("verify-token")]
    public IActionResult VerifyToken()
    {
        // Extract token from the "Authorization" header
        var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return Unauthorized(new { meta = new { code = 0, message = "Authorization header is missing or invalid." } });
        }
        var authToken = authHeader.Substring("Bearer ".Length).Trim(); // Extract token value
        var isValid = _tokenService.VerifyAuthToken(authToken);
        if (!isValid)
        {
            return Unauthorized(new { meta = new { code = 0, message = "Invalid or expired token." } });
        }
        return Ok(new { meta = new { code = 1, message = "Token is valid." } });
    }
    // TODO: Implement get user details, like name, email, 

    // TODO: Implement update user details, like name, email, etc.
}