using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ecos.Application.DTOs.Request;
using Ecos.Application.DTOs.Response;
using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Http;

namespace Ecos.Application.Services
{
    public interface IFileManagerService
    {
        Task<FolderResponse> CreateFolderAsync(CreateFolderRequest request , Guid userId);
        Task<FolderResponse> CreateRootFolderAsync();
        Task<(List<FileResponse> uploadedFiles, List<string> failedFiles)> UploadFilesAsync(UploadFileRequest request , Guid userId);
        Task<List<FolderResponse>> GetAllFoldersWithFilesAsync(Guid userId);
        Task<FolderResponse?> GetFolderByIdAsync(Guid folderId);
        Task<bool> DeleteFileAsync(Guid fileId);
        Task<bool> DeleteFolderAsync(Guid folderId);
        Task<FileResponse?> GetFileByIdAsync(Guid fileId);
        Task<(Stream?, string?, string?)> DownloadFileAsync(Guid fileId);

        Task<List<FolderPathItem>> GetFolderPathAsync(Guid folderId);

        Task<List<FolderPathItem>> GetFilePathAsync(Guid fileId);
    }
}
