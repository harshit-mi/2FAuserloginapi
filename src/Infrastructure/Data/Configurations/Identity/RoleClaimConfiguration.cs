using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecos.Infrastructure.Data.Configurations.Identity;

public class RoleClaimConfiguration : IEntityTypeConfiguration<IdentityRoleClaim<string>>
{
    public void Configure(EntityTypeBuilder<IdentityRoleClaim<string>> builder)
    {
        builder.ToTable("role_claims");
        
        builder.Property(e => e.Id).HasColumnName("id");
        builder.Property(e => e.RoleId).HasColumnName("role_id");
        builder.Property(e => e.ClaimType).HasColumnName("claim_type");
        builder.Property(e => e.ClaimValue).HasColumnName("claim_value");
    }
}