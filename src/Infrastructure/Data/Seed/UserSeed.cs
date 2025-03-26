using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Ecos.Infrastructure.Data.Seed;

public static class UserSeed
{
    public static async Task SeedRolesAndAdminsAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

        // Create roles if they don't exist
        await CreateRoleIfNotExistsAsync(roleManager, RoleConstants.Admin);

        // Create Admin user
        const string admin1Email = "admin@ecos.com";
        User? adminUser = await CreateUserIfNotExistsAsync(userManager, admin1Email, "Admin1@123");
        if (adminUser != null)
        {
            await userManager.AddToRoleAsync(adminUser, RoleConstants.Admin);
        }
    }

    private static async Task CreateRoleIfNotExistsAsync(RoleManager<IdentityRole> roleManager, string roleName)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }

    private static async Task<User?> CreateUserIfNotExistsAsync(UserManager<User> userManager, string email,
        string password)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user != null)
        {
            return user;
        }

        user = new User { UserName = email, Email = email, EmailConfirmed = true };

        var result = await userManager.CreateAsync(user, password);
        return !result.Succeeded ? null : user;
    }
}