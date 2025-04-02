using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Ecos.Application.DTOs.Request;
using Ecos.Application.DTOs.Response;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Ecos.Application.Services
{
    public class FileManagerService : IFileManagerService
    {
        private readonly DataContext _context;
        private readonly BlobServiceClient _blobServiceClient;
        private readonly string _containerName;

        public FileManagerService(DataContext context, BlobServiceClient blobServiceClient, IConfiguration configuration)
        {
            _context = context;
            _blobServiceClient = blobServiceClient;
            _containerName = configuration["Azure:StorageAccount:ContainerName"].ToLower();
        }

        public async Task<FolderResponse> CreateFolderAsync(CreateFolderRequest request, Guid userId)
        {
            // Validate Parent Folder (if provided)
            Folder? parentFolder = null;
            if (request.ParentFolderId.HasValue)
            {
                parentFolder = await _context.Folders.FindAsync(request.ParentFolderId.Value);
                if (parentFolder == null)
                {
                    return null; // Parent folder does not exist
                }
            }

            // Create the new folder (Root folder if ParentFolderId is null)
            var folder = new Folder
            {
                Id = Guid.NewGuid(),  // Assign a new GUID
                Name = request.Name,
                ParentFolderId = request.ParentFolderId, // Null means it's a root folder
                UserId = userId, // Associate folder with the user
                CreatedAt = DateTime.UtcNow
            };

            await _context.Folders.AddAsync(folder);
            await _context.SaveChangesAsync();

            return new FolderResponse(
                folder.Id,
                folder.Name,
                new List<FileResponse>(),
                new List<FolderResponse>()
            );
        }

        public async Task<(List<FileResponse> uploadedFiles, List<string> failedFiles)> UploadFilesAsync(UploadFileRequest request,Guid userId)
        {
            var container = _blobServiceClient.GetBlobContainerClient(_containerName);
            await container.CreateIfNotExistsAsync(PublicAccessType.None);

            var uploadedFiles = new List<FileResponse>();
            var failedFiles = new List<string>();

            foreach (var file in request.Files)
            {
                try
                {
                    var fileId = Guid.NewGuid();
                    var uniqueFileName = $"{Path.GetFileNameWithoutExtension(file.FileName)}_{fileId}{Path.GetExtension(file.FileName)}";
                    var blob = container.GetBlobClient(uniqueFileName);

                    await using var stream = file.OpenReadStream();
                    await blob.UploadAsync(stream, new BlobHttpHeaders { ContentType = file.ContentType });

                    var fileMetadata = new FileMetadata
                    {
                        Id= fileId,
                        Name = file.FileName,
                        ContentType = file.ContentType,
                        Size = file.Length,
                        BlobStorageUrl = blob.Uri.ToString(),
                        UserId= userId,
                        FolderId = request.FolderId
                    };

                    await _context.Files.AddAsync(fileMetadata);
                    uploadedFiles.Add(new FileResponse(fileMetadata.Id, fileMetadata.Name, fileMetadata.BlobStorageUrl));
                }
                catch (Exception ex)
                {
                    failedFiles.Add(file.FileName);
                }
            }

            await _context.SaveChangesAsync();
            return (uploadedFiles, failedFiles);
        }


        public async Task<List<FolderResponse>> GetAllFoldersWithFilesAsync(Guid userId)
        {
            var rootFolders = await _context.Folders
                .Where(f => f.ParentFolderId == null && f.UserId == userId) // Filter by userId
                .Include(f => f.Files.Where(file => file.UserId == userId)) // Ensure only user’s files
                .Include(f => f.SubFolders)
                    .ThenInclude(sf => sf.Files.Where(file => file.UserId == userId)) // Filter subfolder files
                .ToListAsync();

            return rootFolders.Select(f => MapFolderToResponse(f)).ToList();
        }

        private FolderResponse MapFolderToResponse(Folder folder)
        {
            return new FolderResponse(
                folder.Id,
                folder.Name,
                folder.Files.Select(file => new FileResponse(file.Id, file.Name, file.BlobStorageUrl)).ToList(),
                folder.SubFolders.Select(sf => MapFolderToResponse(sf)).ToList() // Recursive mapping
            );
        }

        public async Task<FolderResponse?> GetFolderByIdAsync(Guid folderId)
        {
            var folder = await _context.Folders
                .Where(f => f.Id == folderId)
                .Include(f => f.Files)
                .Include(f => f.SubFolders)
                .ThenInclude(sf => sf.Files)
                .FirstOrDefaultAsync();

            return folder != null ? MapFolderToResponse(folder) : null;
        }

        public async Task<bool> DeleteFileAsync(Guid fileId)
        {
            var file = await _context.Files.FindAsync(fileId);
            if (file == null) return false;
            _context.Files.Remove(file);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteFolderAsync(Guid folderId)
        {
            var folder = await _context.Folders.Include(f => f.SubFolders).FirstOrDefaultAsync(f => f.Id == folderId);
            if (folder == null || folder.SubFolders.Any()) return false;
            _context.Folders.Remove(folder);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<FileResponse?> GetFileByIdAsync(Guid fileId)
        {
            var file = await _context.Files.FindAsync(fileId);
            return file != null ? new FileResponse(file.Id, file.Name, file.BlobStorageUrl) : null;
        }

        public async Task<(Stream?, string?, string?)> DownloadFileAsync(Guid fileId)
        {
            var file = await _context.Files.FindAsync(fileId);
            if (file == null) return (null, null, null);

            var uniqueFileName = $"{Path.GetFileNameWithoutExtension(file.Name)}_{file.Id}{Path.GetExtension(file.Name)}";

            var container = _blobServiceClient.GetBlobContainerClient(_containerName);
            var blob = container.GetBlobClient(uniqueFileName);

            if (!await blob.ExistsAsync()) return (null, null, null);

            var stream = new MemoryStream();
            await blob.DownloadToAsync(stream);
            stream.Position = 0;

            return (stream, file.Name, file.ContentType);
        }
    }
}
