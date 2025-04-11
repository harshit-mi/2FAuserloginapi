using Moq;
using Xunit;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Ecos.Api.Controllers;
using Ecos.Application.DTOs.Request;
using Ecos.Application.Services;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Ecos.Api.Emails.Templates.Models;
using System.Threading.Tasks;
using Ecos.Domain.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Net;
using System.Security.Claims;
using System.Web;
using Microsoft.Extensions.Configuration;

namespace Ecos.Api.Tests.Controllers
{
    public class AuthControllerTests
    {
        private readonly Mock<UserManager<User>> _mockUserManager;
        private readonly Mock<SignInManager<User>> _mockSignInManager;
        private readonly Mock<ILogger<AuthController>> _mockLogger;
        private readonly Mock<IAuthLogTableService> _mockAuthLogTableService;
        private readonly Mock<IEmailCommunicationService> _mockEmailService;
        private readonly Mock<ITokenService> _mockTokenService;
        private readonly Mock<ILoggingService> _mockLogService;
        private readonly Mock<IConfiguration> _mockConfigration;
        private readonly AuthController _controller;

        public AuthControllerTests()
        {
            // Create a mock UserManager
            _mockUserManager = new Mock<UserManager<User>>(
                Mock.Of<IUserStore<User>>(), // Use `Mock.Of<T>()` instead of creating a proxy
                null, null, null, null, null, null, null, null
            );

            // Create a mock SignInManager
            _mockSignInManager = new Mock<SignInManager<User>>(
                _mockUserManager.Object,
                Mock.Of<IHttpContextAccessor>(),
                Mock.Of<IUserClaimsPrincipalFactory<User>>(),
                null, null, null, null
            );

            // Create other service mocks
            _mockLogger = new Mock<ILogger<AuthController>>();
            _mockAuthLogTableService = new Mock<IAuthLogTableService>();
            _mockEmailService = new Mock<IEmailCommunicationService>();
            _mockTokenService = new Mock<ITokenService>();
            _mockLogService = new Mock<ILoggingService>();
            _mockConfigration = new Mock<IConfiguration>();

            // Instantiate the AuthController with mocked dependencies
            _controller = new AuthController(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                _mockLogger.Object,
                _mockAuthLogTableService.Object,
                _mockEmailService.Object,
                _mockTokenService.Object,
                _mockLogService.Object,
                _mockConfigration.Object
            );

            // Set up HttpContext with a fake IP
            var httpContext = new DefaultHttpContext();
            httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };
        }

        [Fact]
        public async Task Login_ReturnsBadRequest_WhenUserNotFound()
        {
            // Arrange
            var loginRequest = new LoginRequest { Email = "nonexistentuser@example.com", Password = "password123" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((User)null);



            // Act
            var result = await _controller.Login(loginRequest);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.NotNull(actionResult);
            Assert.Equal(400, actionResult.StatusCode);

            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);

            // Debugging output
            Console.WriteLine($"Raw Response: {jsonString}");

            // Check if response contains a meta field
            if (response.meta != null)
            {
                Assert.Equal(0, (int)response.meta.code);
                Assert.Equal("Invalid email or password", (string)response.meta.message);
            }
            else
            {
                Assert.Equal(0, (int)response.code);
                Assert.Equal("Invalid email or password", (string)response.message);
            }
        }

        [Fact]
        public async Task Login_ReturnsOk_WhenUserExistsAndPasswordIsCorrect()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };

            _mockUserManager
                .Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(user);

            _mockSignInManager
                .Setup(x => x.CheckPasswordSignInAsync(It.IsAny<User>(), It.IsAny<string>(), It.IsAny<bool>()))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            var loginRequest = new LoginRequest { Email = "user@example.com", Password = "password123" };

            // Act
            var result = await _controller.Login(loginRequest);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);

            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);

            // Debugging output to verify structure
            Console.WriteLine($"Raw Response: {jsonString}");

            Assert.Equal("Verification code sent to your email", (string)response.meta.message);
        }

        [Fact]
        public async Task Login_ReturnsBadRequest_WhenPasswordIncorrect()
        {
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, It.IsAny<string>(), false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Failed);

            var loginRequest = new LoginRequest { Email = "user@example.com", Password = "wrongpassword" };

            var result = await _controller.Login(loginRequest);

            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, actionResult.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid email or password", (string)response.meta.message);
        }

        [Fact]
        public async Task Login_ReturnsBadRequest_WhenUserLockedOut()
        {
            var user = new User { Id = "2", Email = "lockedout@example.com", UserName = "lockeduser" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, It.IsAny<string>(), false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);

            var loginRequest = new LoginRequest { Email = "lockedout@example.com", Password = "password123" };

            var result = await _controller.Login(loginRequest);

            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid email or password", (string)response.meta.message);
        }

        [Fact]
        public async Task Login_LogsAttempt_WhenUserNotFound()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                Email = "missing@example.com",
                Password = "somepass"
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(loginRequest.Email))
                .ReturnsAsync((User)null);

            // Act
            var result = await _controller.Login(loginRequest);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.NotNull(actionResult);
            Assert.Equal(400, actionResult.StatusCode);

            // Deserialize result to dynamic to check response content
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid email or password", (string)response.meta.message);
        }


        [Fact]
        public async Task Login_SendsVerificationEmail_WhenSuccessful()
        {
            var user = new User { Id = "4", Email = "emailuser@example.com", UserName = "emailuser" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, It.IsAny<string>(), false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockEmailService.Setup(x => x.RenderViewToStringAsync("VerificationCode.cshtml", It.IsAny<object>()))
                .ReturnsAsync("RenderedHtml").Verifiable();

            _mockEmailService.Setup(x => x.SendEmailAsync(user.Email, "Your login verification code", "RenderedHtml"))
                .Returns(Task.CompletedTask).Verifiable();

            var loginRequest = new LoginRequest { Email = user.Email, Password = "password" };

            var result = await _controller.Login(loginRequest);

            _mockEmailService.VerifyAll();
        }

        [Fact]
        public async Task VerifyCode_ReturnsBadRequest_WhenUserNotFound()
        {
            // Arrange
            var request = new VerifyCodeRequest { Email = "nonexistentuser@example.com", Code = "123456" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((User)null);

            // Act
            var result = await _controller.VerifyCode(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Invalid email or password", (string)response.meta.message);
        }

        [Fact]
        public async Task VerifyCode_ReturnsBadRequest_WhenCodeIsInvalid()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            var request = new VerifyCodeRequest { Email = "user@example.com", Code = "123456" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<User>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync("654321");

            // Act
            var result = await _controller.VerifyCode(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Invalid verification code", (string)response.meta.message);
        }

        [Fact]
        public async Task VerifyCode_ReturnsBadRequest_WhenCodeOrExpirationMissing()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            var request = new VerifyCodeRequest { Email = "user@example.com", Code = "123456" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode")).ReturnsAsync((string)null!);
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires")).ReturnsAsync("some-exp");

            // Act
            var result = await _controller.VerifyCode(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("No verification code found", (string)response.meta.message);
        }

        [Fact]
        public async Task VerifyCode_ReturnsOk_WhenCodeIsValidAndNotExpired()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            var request = new VerifyCodeRequest { Email = "user@example.com", Code = "123456" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode")).ReturnsAsync("123456");
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires")).ReturnsAsync(DateTime.UtcNow.AddMinutes(10).ToString("o"));
            _mockTokenService.Setup(x => x.GenerateAuthToken(user.Id, user.UserName)).Returns("mocked_token");
            _mockTokenService.Setup(x => x.GenerateRefreshToken()).Returns("refresh_token");
            _mockTokenService.Setup(x => x.StoreRefreshTokenAsync(user.Id, "refresh_token")).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.VerifyCode(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Login successful", (string)response.meta.message);
            Assert.Equal("mocked_token", (string)response.data.authtoken);
            Assert.Equal("refresh_token", (string)response.data.RefreshToken);
        }

        [Fact]
        public async Task VerifyCode_LogsAttempt_WhenCodeIsInvalid()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            var request = new VerifyCodeRequest { Email = "user@example.com", Code = "123456" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCode")).ReturnsAsync("000000");
            _mockUserManager.Setup(x => x.GetAuthenticationTokenAsync(user, "LoginProvider", "VerificationCodeExpires")).ReturnsAsync(DateTime.UtcNow.AddMinutes(10).ToString("o"));

            // Act
            var result = await _controller.VerifyCode(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Invalid verification code", (string)response.meta.message);

        }

        [Fact]
        public async Task ForgotPassword_ReturnsOk_WhenUserNotFound()
        {
            // Arrange
            var request = new ForgotPasswordRequest { Email = "nonexistentuser@example.com" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((User)null);

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("If your email exists in our system, you will receive a password reset link.", (string)response.meta.message);
        }

        [Fact]
        public async Task ForgotPassword_ReturnsOk_WhenUserExists_AndEmailSent()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            var request = new ForgotPasswordRequest { Email = user.Email };
            string token = "mocked-reset-token";
            string encodedToken = HttpUtility.UrlEncode(token);
            string expectedResetUrl = $"http://localhost/reset-password?token={encodedToken}";

            _mockUserManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync(token);
            _mockEmailService.Setup(x => x.RenderViewToStringAsync("ForgotPassword.cshtml", It.IsAny<object>())).ReturnsAsync("mocked_email_body");
            _mockEmailService.Setup(x => x.SendEmailAsync(user.Email, "Reset Your Password", "mocked_email_body")).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("If your email exists in our system, you will receive a password reset link.", (string)response.meta.message);

            _mockEmailService.Verify(x => x.SendEmailAsync(user.Email, "Reset Your Password", "mocked_email_body"), Times.Once);
        }

        [Fact]
        public async Task ForgotPassword_GeneratesResetToken_ForValidUser()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com" };
            var request = new ForgotPasswordRequest { Email = user.Email };

            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync("reset-token");
            _mockEmailService.Setup(x => x.RenderViewToStringAsync("ForgotPassword.cshtml", It.IsAny<object>())).ReturnsAsync("mocked_email_body");
            _mockEmailService.Setup(x => x.SendEmailAsync(user.Email, It.IsAny<string>(), It.IsAny<string>())).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            _mockUserManager.Verify(x => x.GeneratePasswordResetTokenAsync(user), Times.Once);
        }


        [Fact]
        public async Task ForgotPassword_ReturnsOk_IfTokenGenerationFails()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com" };
            var request = new ForgotPasswordRequest { Email = user.Email };

            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync((string)null); // Simulate failure

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("If your email exists in our system, you will receive a password reset link.", (string)response.meta.message);
        }

        [Fact]
        public async Task ForgotPassword_EncodesResetTokenInUrl()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com" };
            var request = new ForgotPasswordRequest { Email = user.Email };
            string resetToken = "token+with/special=chars==";
            string encodedToken = HttpUtility.UrlEncode(resetToken);

            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync(resetToken);

            ForgotPasswordViewModel capturedModel = null;
            _mockEmailService
                .Setup(x => x.RenderViewToStringAsync("ForgotPassword.cshtml", It.IsAny<ForgotPasswordViewModel>()))
                .Callback<string, object>((viewName, model) => capturedModel = (ForgotPasswordViewModel)model)
                .ReturnsAsync("mocked_email");

            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                             .Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            Assert.NotNull(capturedModel);
            Assert.Contains(encodedToken, capturedModel.ResetUrl);
        }

        [Fact]
        public async Task ForgotPassword_RendersCorrectEmailTemplate()
        {
            // Arrange
            var user = new User { Id = "1", Email = "user@example.com" };
            var request = new ForgotPasswordRequest { Email = user.Email };
            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync("valid-token");

            string renderedTemplate = "mocked email content";
            _mockEmailService.Setup(x =>
                x.RenderViewToStringAsync("ForgotPassword.cshtml", It.IsAny<object>())).ReturnsAsync(renderedTemplate);

            _mockEmailService.Setup(x =>
                x.SendEmailAsync(user.Email, "Reset Your Password", renderedTemplate)).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ForgotPassword(request);

            // Assert
            _mockEmailService.Verify(x =>
                x.RenderViewToStringAsync("ForgotPassword.cshtml", It.IsAny<object>()), Times.Once);
        }

        [Fact]
        public async Task ResetPassword_ReturnsBadRequest_WhenTokenIsInvalid()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "invalid_token", NewPassword = "newpassword123" };
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            _mockUserManager.Setup(x => x.Users).Returns(new List<User> { user }.AsQueryable());

            // Act
            var result = await _controller.ResetPassword(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Invalid or expired token.", (string)response.meta.message);
        }

        [Fact]
        public async Task ResetPassword_ReturnsBadRequest_WhenResetFails()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "valid_token", NewPassword = "weakpass" };
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };

            _mockUserManager.Setup(x => x.Users).Returns(new List<User> { user }.AsQueryable());
            _mockUserManager.Setup(x => x.VerifyUserTokenAsync(user,
                It.IsAny<string>(), "ResetPassword", It.IsAny<string>())).ReturnsAsync(true);

            var identityResult = IdentityResult.Failed(new IdentityError { Description = "Password too weak" });
            _mockUserManager.Setup(x => x.ResetPasswordAsync(user, It.IsAny<string>(), It.IsAny<string>()))
                            .ReturnsAsync(identityResult);

            // Act
            var result = await _controller.ResetPassword(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("Password reset failed.", (string)response.meta.message);
            Assert.Contains("Password too weak", (string)response.meta.errors);
        }

        [Fact]
        public async Task ResetPassword_ReturnsOk_WhenResetIsSuccessful()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "valid_token", NewPassword = "StrongPassword@123" };
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };

            _mockUserManager.Setup(x => x.Users).Returns(new List<User> { user }.AsQueryable());
            _mockUserManager.Setup(x => x.VerifyUserTokenAsync(user,
                It.IsAny<string>(), "ResetPassword", It.IsAny<string>())).ReturnsAsync(true);

            _mockUserManager.Setup(x => x.ResetPasswordAsync(user, It.IsAny<string>(), It.IsAny<string>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockTokenService.Setup(x => x.GenerateAuthToken(user.Id, user.UserName)).Returns("auth-token");
            _mockTokenService.Setup(x => x.GenerateRefreshToken()).Returns("refresh-token");
            _mockTokenService.Setup(x => x.StoreRefreshTokenAsync(user.Id, "refresh-token"))
                             .Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ResetPassword(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Your password has been reset successfully.", (string)response.meta.message);
            Assert.Equal("auth-token", (string)response.data.authtoken);
            Assert.Equal("refresh-token", (string)response.data.RefreshToken);
        }

        [Fact]
        public async Task ResetPassword_TriesAllUsersUntilTokenMatches()
        {
            // Arrange
            var user1 = new User { Id = "1", Email = "user1@example.com" };
            var user2 = new User { Id = "2", Email = "user2@example.com", UserName = "user2" };

            var request = new ResetPasswordRequest { ResetToken = "valid_token", NewPassword = "Strong123@" };

            _mockUserManager.Setup(x => x.Users).Returns(new List<User> { user1, user2 }.AsQueryable());

            // First user fails token validation, second passes
            _mockUserManager.SetupSequence(x => x.VerifyUserTokenAsync(It.IsAny<User>(),
                It.IsAny<string>(), "ResetPassword", It.IsAny<string>()))
                .ReturnsAsync(false)
                .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.ResetPasswordAsync(user2, It.IsAny<string>(), It.IsAny<string>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockTokenService.Setup(x => x.GenerateAuthToken(user2.Id, user2.UserName)).Returns("token");
            _mockTokenService.Setup(x => x.GenerateRefreshToken()).Returns("refresh-token");

            // Act
            var result = await _controller.ResetPassword(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("user2@example.com", (string)response.data.email);
        }

        [Fact]
        public async Task RefreshToken_ReturnsUnauthorized_WhenAuthorizationHeaderIsMissing()
        {
            // Arrange
            var request = new RefreshTokenRequest { RefreshToken = "refresh_token" };

            // Act
            var result = await _controller.RefreshToken(request);

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Authorization header is missing or invalid.", (string)response.meta.message);
        }

        [Fact]
        public async Task RefreshToken_ReturnsUnauthorized_WhenRefreshTokenFails()
        {
            // Arrange
            var request = new RefreshTokenRequest { RefreshToken = "invalid_refresh_token" };
            var authToken = "validAuthToken";

            // Simulate Authorization header
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
            _controller.ControllerContext.HttpContext.Request.Headers["Authorization"] = $"Bearer {authToken}";

            _mockTokenService.Setup(x => x.RefreshAuthTokenAsync(authToken, request.RefreshToken))
                             .ReturnsAsync((string)null);

            // Act
            var result = await _controller.RefreshToken(request);

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("Invalid refresh token or expired session.", (string)response.meta.message);
        }

        [Fact]
        public async Task RefreshToken_ReturnsOk_WhenSuccessful()
        {
            // Arrange
            var request = new RefreshTokenRequest { RefreshToken = "valid_refresh_token" };
            var authToken = "oldAuthToken";
            var newAuthToken = "newAuthToken";

            // Simulate Authorization header
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
            _controller.ControllerContext.HttpContext.Request.Headers["Authorization"] = $"Bearer {authToken}";

            _mockTokenService.Setup(x => x.RefreshAuthTokenAsync(authToken, request.RefreshToken))
                             .ReturnsAsync(newAuthToken);

            // Act
            var result = await _controller.RefreshToken(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Token refreshed successfully.", (string)response.meta.message);
            Assert.Equal(newAuthToken, (string)response.data.authToken);
            Assert.Equal("valid_refresh_token", (string)response.data.refreshToken);
        }

        [Fact]
        public async Task RefreshToken_ReturnsUnauthorized_WhenBearerIsMalformed()
        {
            // Arrange
            var request = new RefreshTokenRequest { RefreshToken = "refresh_token" };

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
            _controller.ControllerContext.HttpContext.Request.Headers["Authorization"] = $"TokenOnlyWithoutBearer";

            // Act
            var result = await _controller.RefreshToken(request);

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("Authorization header is missing or invalid.", (string)response.meta.message);
        }

        [Fact]
        public async Task Logout_ReturnsBadRequest_WhenTokenIsMissing()
        {
            // Arrange
            _mockSignInManager.Setup(x => x.SignOutAsync()).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.Logout();

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Invalid user session", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task Logout_ReturnsOk_WhenLogoutSuccessful()
        {
            // Arrange
            var userId = "123";
            var fakeToken = "Bearer fake-jwt-token";

            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, userId)
    };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            };
            httpContext.Request.Headers["Authorization"] = fakeToken;

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            _mockTokenService.Setup(x => x.BlacklistTokenAsync(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            _mockTokenService.Setup(x => x.GenerateExpiredToken(It.IsAny<string>()))
                .Returns("expired-jwt-token");

            _mockTokenService.Setup(x => x.RevokeRefreshTokenAsync(It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            _mockSignInManager.Setup(x => x.SignOutAsync())
                .Returns(Task.CompletedTask);

            // Act
            var result = await _controller.Logout();

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Logged out successfully", (string)response.meta.message);
            Assert.Equal(1, (int)response.meta.code);
        }

        [Fact]
        public async Task Logout_ReturnsBadRequest_WhenAuthorizationHeaderExistsButEmptyToken()
        {
            // Arrange
            var userId = "123";
            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, userId)
    };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            };
            httpContext.Request.Headers["Authorization"] = "Bearer "; // Empty token

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            // Act
            var result = await _controller.Logout();

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.Equal("Token is missing", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task Logout_ReturnsUnauthorized_WhenNoClaimsPrincipal()
        {
            // Arrange
            var httpContext = new DefaultHttpContext(); // No claims set
            httpContext.Request.Headers["Authorization"] = "Bearer some-token";

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            // Act
            var result = await _controller.Logout();

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.Equal("Invalid user session", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task ResendCode_ReturnsOk_WhenCodeResentSuccessfully()
        {
            // Arrange
            var request = new ResendCodeRequest { Email = "user@example.com" };
            var user = new User { Id = "1", Email = "user@example.com", UserName = "user" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _mockEmailService.Setup(x => x.RenderViewToStringAsync(It.IsAny<string>(), It.IsAny<object>())).ReturnsAsync("emailBody");
            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>())).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.ResendCode(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            // Convert response to JSON string and deserialize into a dynamic object
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Verification code sent to your email", (string)response.meta.message);
        }

        [Fact]
        public async Task ResendCode_ReturnsBadRequest_WhenUserNotFound()
        {
            // Arrange
            var request = new ResendCodeRequest { Email = "nonexistent@example.com" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((User)null);

            // Act
            var result = await _controller.ResendCode(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal("Invalid resend attempt", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public void VerifyToken_ReturnsOk_WhenTokenIsValid()
        {
            // Arrange
            var token = "valid-jwt-token";
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            _mockTokenService.Setup(x => x.VerifyAuthToken(token)).Returns(true);

            // Act
            var result = _controller.VerifyToken();

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.Equal("Token is valid.", (string)response.meta.message);
            Assert.Equal(1, (int)response.meta.code);
        }

        [Fact]
        public void VerifyToken_ReturnsUnauthorized_WhenAuthorizationHeaderMissing()
        {
            // Arrange
            var httpContext = new DefaultHttpContext(); // No headers

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            // Act
            var result = _controller.VerifyToken();

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.Equal("Authorization header is missing or invalid.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public void VerifyToken_ReturnsUnauthorized_WhenTokenIsInvalid()
        {
            // Arrange
            var token = "invalid-jwt-token";
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            _mockTokenService.Setup(x => x.VerifyAuthToken(token)).Returns(false);

            // Act
            var result = _controller.VerifyToken();

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.Equal("Invalid or expired token.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

    }
}
