using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Ecos.Infrastructure.Data.Seed
{
    public class FolderSeed
    {
        private static readonly Guid RootFolderId = Guid.NewGuid();
        private static readonly string RootFolderName = "Root";
        private static readonly string AdminEmail = "admin@ecos.com";

        public static async Task SeedRootFolderAsync(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<DataContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

            // Find the Admin user
            var adminUser = await userManager.FindByEmailAsync(AdminEmail);
            if (adminUser == null)
            {
                Console.WriteLine("Admin user not found. Skipping root folder seed.");
                return;
            }

            // Check if the root folder already exists
            var existingRootFolder = await dbContext.Folders
                .FirstOrDefaultAsync(f => f.ParentFolderId == null && f.UserId == Guid.Parse(adminUser.Id));

            if (existingRootFolder != null)
            {
                Console.WriteLine("Root folder already exists.");
                return;
            }

            // Create and add the root folder
            var rootFolder = new Folder
            {
                Id = RootFolderId,
                Name = RootFolderName,
                ParentFolderId = null,
                UserId = Guid.Parse(adminUser.Id),
                CreatedAt = DateTime.UtcNow
            };

            dbContext.Folders.Add(rootFolder);
            await dbContext.SaveChangesAsync();

            Console.WriteLine("Root folder created successfully.");
        }
    }
}
