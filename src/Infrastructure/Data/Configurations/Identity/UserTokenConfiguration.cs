using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecos.Infrastructure.Data.Configurations.Identity;

public class UserTokenConfiguration : IEntityTypeConfiguration<IdentityUserToken<string>>
{
    public void Configure(EntityTypeBuilder<IdentityUserToken<string>> builder)
    {
        builder.ToTable("user_tokens");
        
        builder.Property(e => e.UserId).HasColumnName("user_id");
        builder.Property(e => e.LoginProvider).HasColumnName("login_provider");
        builder.Property(e => e.Name).HasColumnName("name");
        builder.Property(e => e.Value).HasColumnName("value");
    }
}