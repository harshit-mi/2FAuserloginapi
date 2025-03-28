﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Ecos.Application.DTOs.Request;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Ecos.Application.Services
{
    public class TokenService
    {
        private readonly string _key;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly DataContext _context;

        public TokenService(IConfiguration configuration, DataContext context)
        {
            _key = configuration["Jwt:Key"];
            _issuer = configuration["Jwt:Issuer"];
            _audience = configuration["Jwt:Audience"];
            _context = context;
        }

        public string GenerateAuthToken(string userId, string username)
        {
            var expirationTime = DateTime.UtcNow.AddMinutes(1); // Token expires in 1 minute
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim(ClaimTypes.Name, username),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = expirationTime,
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = creds
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token); 
        }
        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }
        public async Task StoreRefreshTokenAsync(string userId, string refreshToken)
        {
            var token = new RefreshToken
            {
                UserId = userId,
                Token = refreshToken,
                ExpiryDate = DateTime.UtcNow.AddDays(7),
                IssuedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            _context.RefreshTokens.Add(token);
            await _context.SaveChangesAsync();
        }
        public async Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken)
        {
            var storedToken = await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.Token == refreshToken && !t.IsRevoked)
            .FirstOrDefaultAsync();
            return storedToken != null && storedToken.ExpiryDate > DateTime.UtcNow;
        }
        public async Task RevokeRefreshTokenAsync(string userId)
        {
            var storedToken = await _context.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .FirstOrDefaultAsync();
            if (storedToken != null)
            {
                storedToken.IsRevoked = true;
                await _context.SaveChangesAsync();
            }
        }
        public async Task<string?> RefreshAuthTokenAsync(string authToken, string refreshToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ReadToken(authToken) as JwtSecurityToken;
            if (principal == null || !principal.Claims.Any())
                return null;
            var userId = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            var username = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            if (userId == null || username == null)
                return null;
            var storedToken = await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.Token == refreshToken && !t.IsRevoked)
            .FirstOrDefaultAsync();
            if (storedToken == null || storedToken.ExpiryDate <= DateTime.UtcNow)
                return null;
            return GenerateAuthToken(userId, username);
        }

        public bool VerifyAuthToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_key);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _issuer,
                    ValidateAudience = false,
                    ValidateLifetime = true, // Ensures token is not expired
                    ClockSkew = TimeSpan.Zero // No extra time buffer for expiration
                }, out _);
                return true;
            }
            catch
            {
                return false; // Token is invalid or expired
            }
        }
    }
}
