using System.Text;
using Ecos.Api;
using System.Net;
using Ecos.Api.Constants;
using Ecos.Application.Services;
using Ecos.Domain.Interfaces;
using Ecos.Infrastructure.Data;
using Ecos.Infrastructure.Data.Seed;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Http.Features;
using Ecos.Application.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Listen(IPAddress.Any, 5001, listenOptions =>
    {
        listenOptions.UseHttps();
    });
});


builder.Services.AddApiServices(builder.Configuration);

builder.Services.AddDbContext<DataContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IDataContext>(provider =>
    provider.GetRequiredService<DataContext>());

builder.Services.AddControllers();
builder.Services.AddMemoryCache();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IFileManagerService, FileManagerService>();
builder.Services.AddScoped<ILoggingService, LoggingService>(); // Scoped service
builder.Services.AddSingleton<IServiceScopeFactory>(sp => sp.GetRequiredService<IServiceScopeFactory>());
builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Configure token validation parameters
    var key = builder.Configuration["Jwt:Key"];
    var issuer = builder.Configuration["Jwt:Issuer"];
    var audience = builder.Configuration["Jwt:Audience"];
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
    };
    // Add events to check for blacklisted tokens
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            // Store the exception in HttpContext for later use in OnChallenge
            context.HttpContext.Items["AuthException"] = context.Exception;
            return Task.CompletedTask;
        },
        OnTokenValidated = async context =>
        {
            var tokenService = context.HttpContext.RequestServices.GetRequiredService<ITokenService>();
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (!string.IsNullOrEmpty(token) && tokenService.IsTokenBlacklisted(token))
            {
                context.Fail("Token has been revoked");

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";

                var response = new
                {
                    meta = new
                    {
                        code = 0,
                        message = new List<string> { "Token has been revoked." }
                    }
                };

                await context.Response.WriteAsJsonAsync(response);
                await context.Response.CompleteAsync(); // Ensure response is written
            }
        },
        OnChallenge = async context =>
        {
            var path = context.HttpContext.Request.Path.Value;

            if (path != null && path.Contains("/auth/refresh-token", StringComparison.OrdinalIgnoreCase))
            {
                // Skip handling here — let the controller handle it
                return;
            }

            context.HandleResponse(); // Prevent default response

            var authException = context.HttpContext.Items["AuthException"] as Exception;

            if (authException is SecurityTokenExpiredException)
            {
                context.Response.StatusCode = 498;
                context.Response.ContentType = "application/json";

                var expiredResponse = new
                {
                    meta = new
                    {
                        code = 0,
                        message = "Token has expired. Please log in again."
                    }
                };

                await context.Response.WriteAsJsonAsync(expiredResponse);
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";

                var unauthorizedResponse = new
                {
                    meta = new
                    {
                        code = 0,
                        message = "Unauthorized access. Please provide a valid token."
                    }
                };

                await context.Response.WriteAsJsonAsync(unauthorizedResponse);
            }
        },
        OnForbidden = async context =>
        {
            var response = new
            {
                meta = new
                {
                    code = 0,
                    message = "Forbidden: You do not have permission to access this resource."
                }
            };

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(response);
        }
    };
});
builder.Services.AddSingleton(x =>
{
    var configuration = x.GetRequiredService<IConfiguration>();
    var connectionString = configuration["Azure:StorageAccount:ConnectionString"];
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException("Azure Storage connection string is not configured.");
    }
    // Create BlobClientOptions with a specific API version
    var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2021_06_08);
    return new BlobServiceClient(connectionString, options);
});
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer {your JWT token}' in the field below."
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = context =>
    {
        var errors = context.ModelState
        .Where(e => e.Value.Errors.Count > 0)
        .SelectMany(e => e.Value.Errors.Select(err => err.ErrorMessage))
        .ToList();
        var response = new
        {
            meta = new
            {
                code = 0,
                message = errors
            }
        };
        return new BadRequestObjectResult(response);
    };
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy => policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader());
});
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = null; // No limit on request body size
});

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = long.MaxValue; // No limit on multipart form data
});
var app = builder.Build();

app.UseCors("AllowAll");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Ecos API v1"));
}
app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseCors(ApiConstants.DefaultCorsPolicy);
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    dbContext.Database.Migrate();

    // Seed roles and admin users
    await UserSeed.SeedRolesAndAdminsAsync(app.Services);
    
}

app.Run();