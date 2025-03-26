using Ecos.Domain.Interfaces.DependencyInjection;

namespace Ecos.Infrastructure.Services.Azure.Interfaces;

public interface IAuthLogTableService : IScoped
{
    Task LogLoginAttemptAsync(string email, string status, string? ipAddress = null, string? userAgent = null);
    Task LogVerificationCodeAsync(string email, string? ipAddress = null);
    Task LogPasswordResetRequestAsync(string email, string? ipAddress = null);
}