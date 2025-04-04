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

            // Instantiate the AuthController with mocked dependencies
            _controller = new AuthController(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                _mockLogger.Object,
                _mockAuthLogTableService.Object,
                _mockEmailService.Object,
                _mockTokenService.Object
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

    }
}
