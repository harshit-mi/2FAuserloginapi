using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Ecos.Application.DTOs.Request;
using Ecos.Application.DTOs.Response;
using Ecos.Application.Interfaces;
using Ecos.Domain.Entities;
using Ecos.Infrastructure.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Ecos.Application.Services
{
    public class FileManagerService : IFileManagerService
    {
        private readonly DataContext _context;
        private readonly BlobServiceClient _blobServiceClient;
        private readonly UserManager<User> _userManager;
        private readonly string _containerName;

        public FileManagerService(DataContext context, BlobServiceClient blobServiceClient, IConfiguration configuration , UserManager<User> userManager)
        {
            _context = context;
            _blobServiceClient = blobServiceClient;
            _userManager = userManager;
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
                    return null; 
                }
            }
            else
            {
                var rootFolders = await GetAllFoldersWithFilesAsync(userId);

                // If no root folder exists, the system creates one automatically
                if (!rootFolders.Any())
                {
                    var rootFolder = await CreateRootFolderAsync();
                    parentFolder = await _context.Folders.FindAsync(rootFolder.Id);
                }
                else
                {
                    parentFolder = await _context.Folders.FindAsync(rootFolders.First().Id); // Use the existing root folder
                }
            }

            // Create the new folder (Root folder if ParentFolderId is null)
            var folder = new Folder
            {
                Id = Guid.NewGuid(),  // Assign a new GUID
                Name = request.Name,
                ParentFolderId = parentFolder.Id,
                UserId = userId, // Associate folder with the user
                CreatedAt = DateTime.UtcNow
            };

            await _context.Folders.AddAsync(folder);
            await _context.SaveChangesAsync();
            var user = await _userManager.FindByIdAsync(folder.UserId.ToString());
            var username = user?.UserName ?? "Unknown";
            var totalBytes = folder.Files?.Sum(f => f.Size) ?? 0;
            return new FolderResponse(
                folder.Id,
                folder.Name,
                new List<FileResponse>(),
                new List<FolderResponse>(),
                GetFolderPathAsync(folder.Id).Result,
                username,
    folder.CreatedAt,
    FormatSize(totalBytes)
            );
        }

        public async Task<(List<FileResponse> uploadedFiles, List<object> failedFiles)> UploadFilesAsync(UploadFileRequest request, Guid userId)
        {
            var container = _blobServiceClient.GetBlobContainerClient(_containerName);
            await container.CreateIfNotExistsAsync(PublicAccessType.None);

            var uploadedFiles = new List<FileResponse>();
            var failedFiles = new List<object>();

            foreach (var fileItem in request.Files)
            {
                var file = fileItem.File;
                var fileId = fileItem.FileId;

                var fileExists = await _context.Files.FindAsync(fileId);
                if (fileExists != null)
                {
                    failedFiles.Add(new
                    {
                        FileId = fileId,
                        FileName = fileItem.File?.FileName ?? "[null]",
                        Reason = "FileId already exists"
                    });

                    continue;
                }

                var uniqueFileName = $"{Path.GetFileNameWithoutExtension(file.FileName)}_{fileId}{Path.GetExtension(file.FileName)}";
                try
                {
                    //temperory-test
                    if (fileItem.AllowRetry)
                        throw new Exception("Forced failure for retry testing");

                    var blob = container.GetBlobClient(uniqueFileName);

                    await using var stream = file.OpenReadStream();
                    await blob.UploadAsync(stream, new BlobHttpHeaders { ContentType = file.ContentType });

                    var fileMetadata = new FileMetadata
                    {
                        Id = fileId,
                        Name = file.FileName,
                        ContentType = file.ContentType,
                        Size = file.Length,
                        BlobStorageUrl = blob.Uri.ToString(),
                        UserId = userId,
                        FolderId = request.FolderId ?? Guid.NewGuid()
                    };

                    var uploadedByUser = await _userManager.FindByIdAsync(userId.ToString());
                    var uploadedBy = uploadedByUser?.UserName ?? "Unknown";

                    await _context.Files.AddAsync(fileMetadata);

                    uploadedFiles.Add(new FileResponse(
                        fileMetadata.Id,
                        fileMetadata.Name,
                        fileMetadata.BlobStorageUrl,
                        await GetFilePathAsync(fileMetadata.Id),
                        FormatSize(fileMetadata.Size),
                        uploadedBy,
                        fileMetadata.UploadedAt
                    ));
                }
                catch (Exception ex)
                {
                    using var memoryStream = new MemoryStream();
                    await file.CopyToAsync(memoryStream);

                    var retryKey = fileId; // ✅ Use FileId as RetryKey

                    var retryEntry = new FileUploadRetry
                    {
                        RetryKey = retryKey,
                        FileName = file.FileName,
                        ContentType = file.ContentType,
                        Size = file.Length,
                        FileContent = memoryStream.ToArray(),
                        FolderId = request.FolderId ?? Guid.NewGuid(),
                        UserId = userId,
                        RetryCount = 0,
                        IsUploaded = false,
                        Error = ex.Message,
                        CreatedAt = DateTime.UtcNow
                    };

                    await _context.FileUploadRetries.AddAsync(retryEntry);
                    failedFiles.Add(new
                    {
                        FileId = fileId,
                        FileName = file.FileName,
                        Reason = "Upload failed",
                        RetryKey = retryKey,
                        ExceptionMessage = ex.Message
                    });
                }
            }

            await _context.SaveChangesAsync();
            return (uploadedFiles, failedFiles);
        }
        private string FormatSize(long bytes)
        {
            if (bytes >= 1024 * 1024)
                return $"{Math.Round(bytes / (1024.0 * 1024.0), 2)} MB";
            else if (bytes >= 1024)
                return $"{Math.Round(bytes / 1024.0, 2)} KB";
            else
                return $"{bytes} Bytes";
        }
        public async Task<FolderResponse> CreateRootFolderAsync()
        {
            var existingRoot = await _context.Folders
                .FirstOrDefaultAsync(f => f.ParentFolderId == null);

            if (existingRoot != null)
            {
                var user1 = await _userManager.FindByIdAsync(existingRoot.UserId.ToString());
                var username1 = user1?.UserName ?? "Unknown";
                var totalBytes1 = existingRoot.Files?.Sum(f => f.Size) ?? 0;
                return new FolderResponse(existingRoot.Id, existingRoot.Name, new List<FileResponse>(), new List<FolderResponse>(), GetFolderPathAsync(existingRoot.Id).Result, username1 , existingRoot.CreatedAt , FormatSize(totalBytes1));
            }

            var rootFolder = new Folder
            {
                Id = Guid.NewGuid(),
                Name = "Root",
                ParentFolderId = null,
                UserId = null,
                CreatedAt = DateTime.UtcNow
            };

            await _context.Folders.AddAsync(rootFolder);
            await _context.SaveChangesAsync();
            var user = await _userManager.FindByIdAsync(rootFolder.UserId.ToString());
            var username = user?.UserName ?? "Unknown";
            var totalBytes = rootFolder.Files?.Sum(f => f.Size) ?? 0;

            return new FolderResponse(rootFolder.Id, rootFolder.Name, new List<FileResponse>(), new List<FolderResponse>(), GetFolderPathAsync(rootFolder.Id).Result, username, rootFolder.CreatedAt, FormatSize(totalBytes));
        }

        public async Task<List<FolderResponse>> GetAllFoldersWithFilesAsync(Guid userId)
        {
            var rootFolders = await _context.Folders
                .Where(f => f.ParentFolderId == null && f.UserId == null)
                .Select(f => new Folder
                {
                    Id = f.Id,
                    Name = f.Name,
                    UserId = f.UserId,
                    CreatedAt = f.CreatedAt,
                    Files = f.Files.Where(file => file.UserId == userId).ToList(),

                    // Subfolders with only basic details, no files or deeper subfolders
                    SubFolders = f.SubFolders
                        .Where(sf => sf.UserId == userId)
                        .Select(sf => new Folder
                        {
                            Id = sf.Id,
                            Name = sf.Name,
                            UserId = sf.UserId,
                            CreatedAt = sf.CreatedAt,
                            Files = new List<FileMetadata>(),     // Empty
                            SubFolders = new List<Folder>()       // Empty
                        }).ToList()
                }).ToListAsync();

            return rootFolders.Select(f => MapFolderToResponse(f)).ToList();
        }

        private FolderResponse MapFolderToResponse(Folder folder)
        {
            var folderOwner = _userManager.FindByIdAsync(folder.UserId.ToString()).Result;
            var folderUsername = folderOwner?.UserName ?? "Unknown";
            var totalBytes = folder.Files?.Sum(f => f.Size) ?? 0;

            var fileResponses = new List<FileResponse>();
            foreach (var file in folder.Files)
            {
                var uploader = _userManager.FindByIdAsync(file.UserId.ToString()).Result;
                var uploadedBy = uploader?.UserName ?? "Unknown";

                fileResponses.Add(new FileResponse(
                    file.Id,
                    file.Name,
                    file.BlobStorageUrl,
                    GetFilePathAsync(file.Id).Result,
                    FormatSize(file.Size),
                    uploadedBy,
                    file.UploadedAt
                ));
            }

            var subFolders = folder.SubFolders
                .Select(sf => MapFolderToResponse(sf))
                .ToList();

            return new FolderResponse(
                folder.Id,
                folder.Name,
                fileResponses,
                subFolders,
                GetFolderPathAsync(folder.Id).Result,
                folderUsername,
                folder.CreatedAt,
                FormatSize(totalBytes)
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
            var folder = await _context.Folders
                .Include(f => f.SubFolders)
                .Include(f => f.Files)
                .FirstOrDefaultAsync(f => f.Id == folderId);

            if (folder == null) return false;

            await DeleteFolderRecursively(folder);
            await _context.SaveChangesAsync();
            return true;
        }

        private async Task DeleteFolderRecursively(Folder folder)
        {
            // Delete all files in this folder
            foreach (var file in folder.Files.ToList())
            {
                _context.Files.Remove(file);
            }

            // Recursively delete subfolders
            foreach (var subFolder in folder.SubFolders.ToList())
            {
                var loadedSubFolder = await _context.Folders
                    .Include(sf => sf.SubFolders)
                    .Include(sf => sf.Files)
                    .FirstOrDefaultAsync(sf => sf.Id == subFolder.Id);

                if (loadedSubFolder != null)
                {
                    await DeleteFolderRecursively(loadedSubFolder);
                }
            }

            _context.Folders.Remove(folder);
        }

        public async Task<FileResponse?> GetFileByIdAsync(Guid fileId)
        {
            var file = await _context.Files.FindAsync(fileId);
            if (file == null)
            {
                return null;
            }
            var uploadedByUser = await _userManager.FindByIdAsync(file.UserId.ToString());
            var uploadedBy = uploadedByUser?.UserName ?? "Unknown";
            return file != null ? new FileResponse(file.Id, file.Name, file.BlobStorageUrl,GetFilePathAsync(file.Id).Result, FormatSize(file.Size), uploadedBy, file.UploadedAt) : null;
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

        public async Task<List<FolderPathItem>> GetFolderPathAsync(Guid folderId)
        {
            var path = new List<FolderPathItem>();
            var current = await _context.Folders.FindAsync(folderId);

            while (current != null)
            {
                path.Insert(0, new FolderPathItem(current.Id, current.Name));
                if (current.ParentFolderId == null) break;
                current = await _context.Folders.FindAsync(current.ParentFolderId.Value);
            }

            return path;
        }

        public async Task<List<FolderPathItem>> GetFilePathAsync(Guid fileId)
        {
            var path = new List<FolderPathItem>();
            var file = await _context.Files.FindAsync(fileId);

            if (file == null) return path;

            Guid? currentFolderId = file.FolderId;

            // Traverse up the folder tree
            while (currentFolderId != null)
            {
                var folder = await _context.Folders.FindAsync(currentFolderId);
                if (folder == null) break;

                path.Insert(0, new FolderPathItem(folder.Id, folder.Name));
                currentFolderId = folder.ParentFolderId;
            }

            return path;
        }
        public async Task<(bool Success, string? ErrorMessage)> RetryUploadByKeyAsync(Guid retryKey, Guid userId)
        {
            const long MaxFileSize = 100 * 1024 * 1024; // 100MB

            var retry = await _context.FileUploadRetries.FirstOrDefaultAsync(
                r => r.RetryKey == retryKey && r.UserId == userId && !r.IsUploaded && r.RetryCount < 5
            );

            if (retry == null)
                return (false, "Retry not found or already completed.");

            if (retry.Size > MaxFileSize)
                return (false, $"File size exceeds 100MB limit. Size: {(retry.Size / (1024 * 1024)):F2} MB");

            try
            {
                await using var stream = new MemoryStream(retry.FileContent);

                var formFile = new FormFile(stream, 0, retry.Size, "file", retry.FileName)
                {
                    Headers = new HeaderDictionary(),
                    ContentType = retry.ContentType
                };

                var uploadRequest = new UploadFileRequest
                {
                    FolderId = retry.FolderId,
                    Files = new List<FileUploadItem>
            {
                new FileUploadItem
                {
                    FileId = retry.RetryKey,
                    File = formFile
                }
            }
                };

                var (uploaded, failed) = await UploadFilesAsync(uploadRequest, userId);

                if (uploaded.Any())
                {
                    _context.FileUploadRetries.Remove(retry); // Clean up successful retry
                    await _context.SaveChangesAsync();
                    return (true, null);
                }

                retry.RetryCount++;
                retry.Error = "Retry failed";
                await _context.SaveChangesAsync();
                return (false, "Retry failed");
            }
            catch (Exception ex)
            {
                retry.RetryCount++;
                retry.Error = ex.Message;
                await _context.SaveChangesAsync();

                return (false, $"Retry failed with error: {ex.Message}");
            }
        }

        public async Task<bool> RenameFileAsync(Guid fileId, string newName)
        {
            var file = await _context.Files.FirstOrDefaultAsync(f => f.Id == fileId);
            if (file == null) return false;

            // Get current extension
            var currentExtension = Path.GetExtension(file.Name);

            // Remove any extension from the new name
            var baseName = Path.GetFileNameWithoutExtension(newName);

            // Build final name with original extension
            file.Name = $"{baseName}{currentExtension}";

            _context.Files.Update(file);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> RenameFolderAsync(Guid folderId, string newName)
        {
            var folder = await _context.Folders.FirstOrDefaultAsync(f => f.Id == folderId);
            if (folder == null) return false;

            folder.Name = newName;
            _context.Folders.Update(folder);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<GlobalSearchResult> GlobalSearchAsync(string query, Guid userId)
        {
            var lowerQuery = query.ToLower();

            var filesRaw = await _context.Files
                .Where(f => f.Name.ToLower().Contains(lowerQuery) && f.UserId == userId)
                .ToListAsync();

            var foldersRaw = await _context.Folders
                .Where(f => f.Name.ToLower().Contains(lowerQuery) && f.UserId == userId)
                .Include(f => f.Files.Where(file => file.UserId == userId))
                .Include(f => f.SubFolders.Where(sub => sub.UserId == userId))
                .ToListAsync();

            var fileItems = new List<SearchItem>();
            foreach (var file in filesRaw)
            {
                var path = await GetFilePathAsync(file.Id);
                fileItems.Add(new SearchItem
                {
                    Id = file.Id,
                    Name = file.Name,
                    Type = "File",
                    CreatedAt = file.UploadedAt,
                    SizeFormatted = FormatSize(file.Size),
                    Path = path
                });
            }

            var folderItems = new List<SearchItem>();
            foreach (var folder in foldersRaw)
            {
                var path = await GetFolderPathAsync(folder.Id);
                var totalBytes = folder.Files?.Sum(f => f.Size) ?? 0;

                folderItems.Add(new SearchItem
                {
                    Id = folder.Id,
                    Name = folder.Name,
                    Type = "Folder",
                    CreatedAt = folder.CreatedAt,
                    SizeFormatted = FormatSize(totalBytes),
                    Path = path,
                    Files = folder.Files?.Select(f => new SearchItem
                    {
                        Id = f.Id,
                        Name = f.Name,
                        Type = "File",
                        CreatedAt = f.UploadedAt,
                        SizeFormatted = FormatSize(f.Size)
                    }).ToList(),
                    SubFolders = folder.SubFolders?.Select(sf => new SearchItem
                    {
                        Id = sf.Id,
                        Name = sf.Name,
                        Type = "Folder",
                        CreatedAt = sf.CreatedAt
                    }).ToList()
                });
            }

            return new GlobalSearchResult
            {
                Files = fileItems,
                Folders = folderItems
            };
        }
    }
}
