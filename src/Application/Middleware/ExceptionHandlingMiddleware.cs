using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Ecos.Application.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ecos.Application.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _serviceScopeFactory;

        public ExceptionHandlingMiddleware(RequestDelegate next, IServiceScopeFactory serviceScopeFactory)
        {
            _next = next;
            _serviceScopeFactory = serviceScopeFactory;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                // Create a new scope for resolving scoped services
                using var scope = _serviceScopeFactory.CreateScope();
                var loggingService = scope.ServiceProvider.GetRequiredService<LoggingService>();

                // Log the error
              //  await loggingService.LogErrorAsync(ex.Message, ex.StackTrace, "System");

                // Prepare the error response in the required format
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";

                var response = new
                {
                    meta = new
                    {
                        code = 0,
                        message = new List<string> { "An unexpected error occurred." }
                    }
                };

                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            }
        }
    }
}