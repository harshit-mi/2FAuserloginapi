using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ecos.Application.Services
{
    public interface ITokenService
    {
        string GenerateAuthToken(string userId, string username);
        string GenerateRefreshToken();
        Task StoreRefreshTokenAsync(string userId, string refreshToken);
        Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken);
        Task RevokeRefreshTokenAsync(string userId);
        Task<(string? newAuthToken, string? newRefreshToken)> RefreshAuthTokenAsync(string authToken, string refreshToken);
        bool VerifyAuthToken(string token);
    }
}
