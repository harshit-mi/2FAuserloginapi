namespace Ecos.Domain.Interfaces;

public interface IDataContext
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}