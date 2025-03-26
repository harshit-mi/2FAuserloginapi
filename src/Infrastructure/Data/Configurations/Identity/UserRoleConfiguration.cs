using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecos.Infrastructure.Data.Configurations.Identity;

public class UserRoleConfiguration : IEntityTypeConfiguration<IdentityUserRole<string>>
{
    public void Configure(EntityTypeBuilder<IdentityUserRole<string>> builder)
    {
        builder.ToTable("user_roles");
        
        builder.Property(e => e.UserId).HasColumnName("user_id");
        builder.Property(e => e.RoleId).HasColumnName("role_id");
    }
}