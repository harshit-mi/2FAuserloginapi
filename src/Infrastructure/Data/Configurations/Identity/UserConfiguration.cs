using Ecos.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecos.Infrastructure.Data.Configurations.Identity;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");

        builder.Property(e => e.Id).HasColumnName("id");

        // Make UserName required
        builder.Property(e => e.UserName).HasColumnName("username").IsRequired();
        builder.Property(e => e.NormalizedUserName).HasColumnName("normalized_username").IsRequired();

        // Email is already required
        builder.Property(e => e.Email).HasColumnName("email").IsRequired();
        builder.Property(e => e.NormalizedEmail).HasColumnName("normalized_email").IsRequired();

        // Add unique constraints
        builder.HasIndex(e => e.NormalizedUserName).HasDatabaseName("uk_normalized_username").IsUnique();
        builder.HasIndex(e => e.NormalizedEmail).HasDatabaseName("uk_normalized_email").IsUnique();

        builder.Property(e => e.EmailConfirmed).HasColumnName("email_confirmed");
        builder.Property(e => e.PasswordHash).HasColumnName("password_hash");
        builder.Property(e => e.SecurityStamp).HasColumnName("security_stamp");
        builder.Property(e => e.ConcurrencyStamp).HasColumnName("concurrency_stamp");
        builder.Property(e => e.PhoneNumber).HasColumnName("phone_number");
        builder.Property(e => e.PhoneNumberConfirmed).HasColumnName("phone_number_confirmed");
        builder.Property(e => e.TwoFactorEnabled).HasColumnName("two_factor_enabled");
        builder.Property(e => e.LockoutEnd).HasColumnName("lockout_end");
        builder.Property(e => e.LockoutEnabled).HasColumnName("lockout_enabled");
        builder.Property(e => e.AccessFailedCount).HasColumnName("access_failed_count");
    }
}