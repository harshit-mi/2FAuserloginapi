
using Ecos.Domain.Interfaces.DependencyInjection;

namespace Ecos.Infrastructure.Services.Azure.Interfaces
{
    public interface IEmailCommunicationService : IScoped
    {
        Task SendEmailAsync(string to, string subject, string body);
        Task<string> RenderViewToStringAsync<TModel>(string viewPath, TModel model);
    }
}
