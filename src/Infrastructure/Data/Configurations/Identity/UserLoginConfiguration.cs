﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecos.Infrastructure.Data.Configurations.Identity;

public class UserLoginConfiguration : IEntityTypeConfiguration<IdentityUserLogin<string>>
{
    public void Configure(EntityTypeBuilder<IdentityUserLogin<string>> builder)
    {
        builder.ToTable("user_logins");
        
        builder.Property(e => e.LoginProvider).HasColumnName("login_provider");
        builder.Property(e => e.ProviderKey).HasColumnName("provider_key");
        builder.Property(e => e.ProviderDisplayName).HasColumnName("provider_display_name");
        builder.Property(e => e.UserId).HasColumnName("user_id");
    }
}