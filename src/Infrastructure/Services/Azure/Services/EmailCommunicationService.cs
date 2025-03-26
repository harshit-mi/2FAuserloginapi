using Azure;
using Azure.Communication.Email;
using Ecos.Common.Options;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RazorLight;

namespace Ecos.Infrastructure.Services.Azure.Services
{
    public class EmailCommunicationService : IEmailCommunicationService
    {
        private readonly AzureEmailCommunicationOptions _options;
        private readonly RazorLightEngine _razorEngine;
        private readonly ILogger<EmailCommunicationService> _logger;

        public EmailCommunicationService(IOptions<AzureEmailCommunicationOptions> options,
                                            ILogger<EmailCommunicationService> logger)
        {           
            _options = options.Value;
            _logger = logger;
            var basePath = Directory.GetCurrentDirectory();
            _logger.LogInformation("Initializing RazorLight with base path: {BasePath}", basePath);
            _razorEngine = new RazorLightEngineBuilder()
                .UseFileSystemProject(basePath)
                .UseMemoryCachingProvider()
                .Build();
        }

        public async Task<string> RenderViewToStringAsync<TModel>(string viewPath, TModel model)
        {
            try
            {
                string fullPath =  viewPath;
            
                _logger.LogInformation("Attempting to read template from: {FullPath}", fullPath);

                if (!File.Exists(fullPath))
                {
                    _logger.LogError("Template file not found at: {FullPath}", fullPath);
                    throw new FileNotFoundException($"Template file not found at: {fullPath}");
                }

                string template = await File.ReadAllTextAsync(fullPath);
                string templateKey = viewPath.Replace("/", "").Replace("\\", "");

                return await _razorEngine.CompileRenderStringAsync(templateKey, template, model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error rendering template: {ViewPath}", viewPath);
                throw;
            }
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            string connectionString = _options.ConnectionString;
            var emailClient = new EmailClient(connectionString);


            var emailMessage = new EmailMessage(
                senderAddress: _options.SenderAddress,                
                content: new EmailContent(subject)
                {
                    
                    Html = body
                },
                recipients: new EmailRecipients(new List<EmailAddress> { new EmailAddress(to) }));


            EmailSendOperation emailSendOperation = await emailClient.SendAsync(WaitUntil.Completed, emailMessage);
        }
    }

}
