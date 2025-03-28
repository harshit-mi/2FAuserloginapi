using Ecos.Api;
using Ecos.Api.Constants;
using Ecos.Domain.Interfaces;
using Ecos.Infrastructure.Data;
using Ecos.Infrastructure.Data.Seed;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddApiServices(builder.Configuration);

builder.Services.AddDbContext<DataContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IDataContext>(provider =>
    provider.GetRequiredService<DataContext>());

builder.Services.AddControllers();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Ecos API v1"));
}

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