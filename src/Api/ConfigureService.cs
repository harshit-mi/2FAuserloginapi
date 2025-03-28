using System.IO.Compression;
using System.Text;
using Ecos.Api.Constants;
using Ecos.Application.Services;
using Ecos.Common.Options;
using Ecos.Domain.Entities;
using Ecos.Domain.Interfaces;
using Ecos.Domain.Interfaces.DependencyInjection;
using Ecos.Infrastructure.Data;
using Ecos.Infrastructure.Services.Azure.Interfaces;
using Ecos.Infrastructure.Services.Azure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Configuration;


namespace Ecos.Api;

public static class ConfigureService
{
    public static void AddApiServices(this IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddSingleton<ILoggerFactory, LoggerFactory>();
        services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));

        services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Fastest);
        services.AddResponseCompression(options =>
        {
            options.EnableForHttps = true;
            options.Providers.Add<GzipCompressionProvider>();
        });

        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);

        AddDependencyInjection(services);
        AddDbContext(services, configuration);
        AddIdentity(services);
        AddCors(services, configuration);
        AddSwagger(services);
        AddOptions(services, configuration);
    }

    private static void AddDbContext(IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddDbContext<DataContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));

        services.AddScoped<IDataContext>(provider =>
            provider.GetRequiredService<DataContext>());
    }
    
        // Other services

        
    

    private static void AddIdentity(IServiceCollection services)
    {
        services.AddIdentity<User, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;
            })
            .AddEntityFrameworkStores<DataContext>()
            .AddDefaultTokenProviders();

        services
            .AddAuthentication()
            .AddBearerToken("Identity.Bearer");
    }

    private static void AddCors(IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddCors(options =>
        {
            options.AddPolicy(ApiConstants.DefaultCorsPolicy, policy =>
            {
                policy.WithOrigins(configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [])
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
        });
    }

    private static void AddSwagger(IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "Creditech API", Version = "v1" });
        });
    }

    private static void AddOptions(IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddOptions<AzureStorageAccountOptions>()
            .Bind(configuration.GetSection(AzureStorageAccountOptions.SectionName))
            .ValidateOnStart();

        services.AddOptions<AzureEmailCommunicationOptions>()
            .Bind(configuration.GetSection(AzureEmailCommunicationOptions.SectionName))
            .ValidateOnStart();
    }

    private static void AddDependencyInjection(IServiceCollection services)
    {
        services.Scan(scan => scan
            .FromAssemblyOf<ISingleton>()
            .AddClasses(classes => classes.AssignableTo(typeof(ISingleton)).Where(item => !item.IsAbstract))
            .AsImplementedInterfaces()
            .WithSingletonLifetime());

        services.Scan(scan => scan
            .FromAssemblyOf<IScoped>()
            .AddClasses(classes => classes.AssignableTo(typeof(IScoped)).Where(item => !item.IsAbstract))
            .AsImplementedInterfaces()
            .WithScopedLifetime());

        // Custom services
        services.AddScoped<IAuthLogTableService, AuthLogTableService>();
        services.AddScoped<IEmailCommunicationService, EmailCommunicationService>();
        // services.AddSingleton<IEmailSender<User>, NoOpEmailSenderService>();
    }
}