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
using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

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
    private readonly ILoggingService _loggingService;

    public AuthController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        ILogger<AuthController> logger,
        IAuthLogTableService authLogService,
        IEmailCommunicationService emailService,
        ITokenService tokenService,
        ILoggingService loggingService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _authLogTableService = authLogService;
        _emailService = emailService;
        _tokenService = tokenService;
        _loggingService = loggingService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        string? userAgent = Request.Headers.UserAgent.ToString();

        await _loggingService.LogAsync("Login_Attempt_Started", TrackedEntity.User, null, null, null, "Anonymous",
            $"Login attempt initiated for email: {request.Email}");

        User? user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Login attempt with non-existing email: {Email}", request.Email);
            await _loggingService.LogAsync("Login_Failed_UserNotFound", TrackedEntity.User, null, null, null, "Anonymous",
                $"Login failed: User not found for email: {request.Email}");
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress, userAgent);

            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            string status = result.IsLockedOut ? "LockedOut" : "InvalidPassword";
            _logger.LogWarning("Login attempt failed for email: {Email}, Status: {Status}", request.Email, status);

            await _loggingService.LogErrorAsync("Login_Failed_PasswordInvalid", $"Login failed for user: {request.Email}, Status: {status}", user.Id);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, status, ipAddress, userAgent);

            await _loggingService.LogAsync("Login_Attempt_Failed", TrackedEntity.User, null, null, null, user.Id,
                $"Password verification failed for user: {request.Email}");

            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
        }

        string code = Generator.VerifyCode();

        // Store the code with user
        await _userManager.SetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode", code);
        await _loggingService.LogAsync("Login_VerificationCodeGenerated", TrackedEntity.User, null, null, null, user.Id,
            $"Verification code generated for user: {request.Email}");

        // Set expiration token
        await _userManager.SetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires",
            DateTime.UtcNow.AddMinutes(15).ToString("o"));

        await _loggingService.LogAsync("Login_VerificationCodeExpirySet", TrackedEntity.User, null, null, null, user.Id,
            $"Verification code expiry set for user: {request.Email}");

        // Log verification code generation
        await _authLogTableService.LogVerificationCodeAsync(request.Email, ipAddress);

        VerificationCodeViewModel obje = new VerificationCodeViewModel { Code = code };

        // Send email with code
        string emailBody = await _emailService.RenderViewToStringAsync("VerificationCode.cshtml", obje);
        await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);

        await _loggingService.LogAsync("Login_EmailSent", TrackedEntity.User, null, null, null, user.Id,
            $"Verification code email sent to {user.Email}");

        _logger.LogInformation("Login attempt for {Email} successfully", request.Email);

        await _loggingService.LogAsync("Login_VerificationCodeSent", TrackedEntity.User, null, null, null, user.Id,
            "Verification code sent to user’s email");

        return Ok(new { meta = new { code = 1, message = "Verification code sent to your email" } });
    }


    [HttpPost("verify")]
    public async Task<IActionResult> VerifyCode([FromBody] VerifyCodeRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _loggingService.LogAsync("Verification_Attempt_Started", TrackedEntity.User, null, null, null, "Anonymous",
            $"Verification attempt initiated for email: {request.Email}");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Verification attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "UserNotFound", ipAddress);
            await _loggingService.LogErrorAsync("Verification_Failed_UserNotFound", $"User not found: {request.Email}", "Anonymous");

            return BadRequest(new { meta = new { code = 0, message = "Invalid email or password" } });
        }

        // Get stored code and expiration
        var storedCode = await _userManager.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
        var expirationStr = await _userManager.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");

        if (string.IsNullOrEmpty(storedCode) || string.IsNullOrEmpty(expirationStr))
        {
            _logger.LogWarning("No verification code found for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "NoVerificationCode", ipAddress);
            await _loggingService.LogErrorAsync("Verification_Failed_NoCodeStored", "No verification code stored", user.Id);

            return BadRequest(new { meta = new { code = 0, message = "No verification code found" } });
        }

        // Verify code
        if (request.Code != storedCode)
        {
            _logger.LogWarning("Invalid verification code for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "InvalidCode", ipAddress);
            await _loggingService.LogErrorAsync("Verification_Failed_InvalidCode", $"Invalid code used: {request.Code}", user.Id);

            return BadRequest(new { meta = new { code = 0, message = "Invalid verification code" } });
        }

        // Check expiration
        if (!DateTime.TryParse(expirationStr, out var expiration) || expiration < DateTime.UtcNow)
        {
            _logger.LogWarning("Verification code expired for email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ExpiredCode", ipAddress);
            await _loggingService.LogErrorAsync("Verification_Failed_CodeExpired", "Code expired", user.Id);

            return BadRequest(new { meta = new { code = 0, message = "Verification code expired" } });
        }

        // Clear used tokens
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
        await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");

        await _loggingService.LogAsync("Verification_CodeCleared", TrackedEntity.User, null, null, null, user.Id,
            "Verification code and expiration cleared after successful validation");

        string token = _tokenService.GenerateAuthToken(user.Id, user.UserName);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _tokenService.StoreRefreshTokenAsync(user.Id, refreshToken);
        await _loggingService.LogAsync("Login_TokensGenerated", TrackedEntity.User, null, null, null, user.Id,
            "Access and refresh tokens generated and stored");

        await _signInManager.SignInAsync(user, isPersistent: true);

        await _authLogTableService.LogLoginAttemptAsync(request.Email, "Success", ipAddress);
        await _loggingService.LogAsync("Login_Success", TrackedEntity.User, null, null, null, user.Id,
            "User successfully logged in");

        _logger.LogInformation("User {Email} logged in successfully", request.Email);

        return Ok(new
        {
            meta = new { code = 1, message = "Login successful" },
            data = new
            {
                userName = user.UserName,
                email = user.Email,
                authtoken = token,
                RefreshToken = refreshToken
            }
        });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        string? userAgent = Request.Headers.UserAgent.ToString();

        await _loggingService.LogAsync("ForgotPassword_Attempt_Started", TrackedEntity.User, null, null, null, "Anonymous",
            $"Forgot password request initiated for email: {request.Email}");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Password reset attempt with non-existing email: {Email}", request.Email);
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ForgotPassword_UserNotFound", ipAddress, userAgent);
            await _loggingService.LogErrorAsync("ForgotPassword_Failed_UserNotFound", $"No user found with email {request.Email}", "Anonymous");

            // Don't reveal existence of email
            return Ok(new { meta = new { code = 1, message = "If your email exists in our system, you will receive a password reset link." } });
        }

        string token = await _userManager.GeneratePasswordResetTokenAsync(user);
        string encodedToken = HttpUtility.UrlEncode(token);
        string resetUrl = $"{Request.Scheme}://{Request.Host}/reset-password?token={encodedToken}";

        ForgotPasswordViewModel obj = new ForgotPasswordViewModel { ResetUrl = resetUrl };
        string emailBody = await _emailService.RenderViewToStringAsync("ForgotPassword.cshtml", obj);
        await _emailService.SendEmailAsync(user.Email!, "Reset Your Password", emailBody);

        await _authLogTableService.LogLoginAttemptAsync(request.Email, "ForgotPassword_TokenSent", ipAddress, userAgent);

        _logger.LogInformation("Password reset email sent for {Email}", request.Email);
        await _loggingService.LogAsync("ForgotPassword_TokenGeneratedAndEmailSent", TrackedEntity.User, null, null, null, user.Id,
            "Password reset token generated and sent via email");

        return Ok(new { meta = new { code = 1, message = "If your email exists in our system, you will receive a password reset link." } });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var decodedToken = WebUtility.UrlDecode(request.ResetToken);
        string? ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _loggingService.LogAsync("ResetPassword_Attempt_Started", TrackedEntity.User, null, null, null, "Anonymous",
            $"Password reset attempt initiated with token");

        var users = _userManager.Users.ToList();
        User? foundUser = null;

        foreach (var user in users)
        {
            bool isValid = await _userManager.VerifyUserTokenAsync(
                user,
                _userManager.Options.Tokens.PasswordResetTokenProvider,
                "ResetPassword",
                decodedToken);

            if (isValid)
            {
                foundUser = user;
                break;
            }
        }

        if (foundUser == null)
        {
            _logger.LogWarning("Invalid password reset token.");
            await _loggingService.LogErrorAsync("ResetPassword_Failed_InvalidToken", "Invalid or expired reset token", "Anonymous");
            return BadRequest(new { meta = new { code = 0, message = "Invalid or expired token." } });
        }

        string email = foundUser.Email;
        var result = await _userManager.ResetPasswordAsync(foundUser, decodedToken, request.NewPassword);

        if (!result.Succeeded)
        {
            string errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogWarning("Password reset failed for {Email}: {Errors}", email, errors);
            await _authLogTableService.LogLoginAttemptAsync(email, "ResetPassword_Failed", ipAddress);
            await _loggingService.LogErrorAsync("ResetPassword_Failed", $"Password reset failed for {email}. Errors: {errors}", foundUser.Id);

            return BadRequest(new { meta = new { code = 0, message = "Password reset failed.", errors } });
        }

        var authToken = _tokenService.GenerateAuthToken(foundUser.Id, foundUser.UserName);
        var refreshToken = _tokenService.GenerateRefreshToken();
        await _tokenService.StoreRefreshTokenAsync(foundUser.Id, refreshToken);

        await _authLogTableService.LogPasswordResetRequestAsync(email, ipAddress);
        _logger.LogInformation("Password reset successful for {Email}", email);
        await _loggingService.LogAsync("ResetPassword_Success", TrackedEntity.User, null, null, null, foundUser.Id,
            "Password reset completed successfully and tokens generated");

        return Ok(new
        {
            meta = new { code = 1, message = "Your password has been reset successfully." },
            data = new
            {
                userName = foundUser.UserName,
                email = foundUser.Email,
                authtoken = authToken,
                RefreshToken = refreshToken
            }
        });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            await _loggingService.LogErrorAsync(
                "Logout_Failed_InvalidUser",
                "User ID not found in token during logout attempt",
                "Anonymous"
            );
            return Unauthorized(new { meta = new { code = 0, message = "Invalid user session" } });
        }

        var authToken = Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        if (string.IsNullOrEmpty(authToken))
        {
            await _loggingService.LogErrorAsync(
                "Logout_Failed_MissingToken",
                "Authorization token is missing in logout request",
                userId
            );
            return BadRequest(new { meta = new { code = 0, message = "Token is missing" } });
        }

        await _loggingService.LogAsync(
            "Logout_Attempt",
            TrackedEntity.User,
            null,
            null,
            null,
            userId,
            "User initiated logout request"
        );

        // Store the token in a blacklist
        await _tokenService.BlacklistTokenAsync(authToken, userId);

        // Issue an expired token (optional, for frontend cleanup or signaling)
        var expiredToken = _tokenService.GenerateExpiredToken(userId);

        // Revoke the refresh token
        await _tokenService.RevokeRefreshTokenAsync(userId);

        // Sign out user (for Identity-based authentication)
        await _signInManager.SignOutAsync();

        // Log success
        await _loggingService.LogAsync(
            "Logout_Success",
            TrackedEntity.User,
            null,
            null,
            null,
            userId,
            "User successfully logged out, tokens revoked and blacklisted"
        );

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
            await _authLogTableService.LogLoginAttemptAsync(request.Email, "ResendCode_UserNotFound", ipAddress);
            await _loggingService.LogErrorAsync(
                "ResendCode_Failed",
                $"Attempted to resend verification code for non-existent user: {request.Email}",
                "Anonymous"
            );
            return BadRequest(new { meta = new { code = 0, message = "Invalid resend attempt" } });
        }

        // Remove any existing codes and expiration tokens
        var expirationStr = await _userManager.GetAuthenticationTokenAsync(
            user, "LoginProvider", "VerificationCodeExpires");

        if (!string.IsNullOrEmpty(expirationStr))
        {
            await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode");
            await _userManager.RemoveAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires");
        }

        // Generate and store new code and expiration
        string code = Generator.VerifyCode();
        await _userManager.SetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode", code);
        await _userManager.SetAuthenticationTokenAsync(
            user,
            "LoginProvider",
            "VerificationCodeExpires",
            DateTime.UtcNow.AddMinutes(15).ToString("o"));

        // Prepare and send email
        var viewModel = new VerificationCodeViewModel { Code = code };
        string emailBody = await _emailService.RenderViewToStringAsync("VerificationCode.cshtml", viewModel);
        await _emailService.SendEmailAsync(user.Email!, "Your login verification code", emailBody);

        // Logging
        await _authLogTableService.LogVerificationCodeAsync(request.Email, ipAddress);

        await _loggingService.LogAsync(
            "ResendCode_Success",
            TrackedEntity.User,
            null,
            null,
            null,
            user.Id,
            "Verification code resent successfully"
        );

        _logger.LogInformation("Verification code resent for {Email}", request.Email);

        return Ok(new { meta = new { code = 1, message = "Verification code sent to your email" } });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            await _loggingService.LogErrorAsync(
                "RefreshToken_Failed",
                "Authorization header is missing or invalid.",
                "Anonymous"
            );

            return Unauthorized(new { meta = new { code = 0, message = "Authorization header is missing or invalid." } });
        }
      
            var authToken = authHeader.Substring("Bearer ".Length).Trim();
        string newAuthToken = await _tokenService.RefreshAuthTokenAsync(authToken, request.RefreshToken);

        if (newAuthToken == null)
        {
            await _loggingService.LogErrorAsync(
                "RefreshToken_Failed",
                "Invalid refresh token or expired session.",
                "Anonymous"
            );

            return Unauthorized(new { meta = new { code = 0, message = "Invalid refresh token or expired session." } });
        }

        await _loggingService.LogAsync(
            "RefreshToken_Success",
            TrackedEntity.User,
            null,
            null,
            null,
            Guid.Empty.ToString(), 
            "Token refreshed successfully."
        );

        return Ok(new
        {
            meta = new { code = 1, message = "Token refreshed successfully." },
            data = new { authToken = newAuthToken, refreshToken = request.RefreshToken }
        });
    }

    [HttpPost("verify-token")]
    [Authorize]
    public IActionResult VerifyToken()
    {
        var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            _ = _loggingService.LogErrorAsync(
                "VerifyToken_Failed",
                "Authorization header is missing or invalid.",
                "Anonymous"
            );

            return Unauthorized(new { meta = new { code = 0, message = "Authorization header is missing or invalid." } });
        }

        var authToken = authHeader.Substring("Bearer ".Length).Trim();
        var isValid = _tokenService.VerifyAuthToken(authToken);

        if (!isValid)
        {
            _ = _loggingService.LogAsync(
                "VerifyToken_Invalid",
                TrackedEntity.User,
                null,
                null,
                null,
                Guid.Empty.ToString(),
                "Invalid or expired token"
            );

            return Unauthorized(new { meta = new { code = 0, message = "Invalid or expired token." } });
        }

        _ = _loggingService.LogAsync(
            "VerifyToken_Valid",
            TrackedEntity.User,
            null,
            null,
            null,
            Guid.Empty.ToString(),
            "Token is valid"
        );

        return Ok(new { meta = new { code = 1, message = "Token is valid." } });
    }
    // TODO: Implement get user details, like name, email, 

    // TODO: Implement update user details, like name, email, etc.

    //[HttpGet("GetLogs")]
    //public async Task<IActionResult> GetLogs()
    //{
    //    var logs = await _loggingService.GetLogsAsync(null,null);

    //    if (logs == null || !logs.Any())
    //    {
    //        return Ok(new
    //        {
    //            meta = new { code = 0, message = "No logs found" },
    //            data = new List<object>()
    //        });
    //    }

    //    return Ok(new
    //    {
    //        meta = new { code = 1, message = "Logs retrieved successfully" },
    //        data = logs
    //    });
    //}
}