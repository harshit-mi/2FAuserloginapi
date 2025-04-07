using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using Ecos.Api.Controllers.Base;
using Ecos.Application.DTOs.Request;
using Ecos.Application.DTOs.Response;
using Ecos.Application.Services;
using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ecos.Api.Controllers
{
    [Route("file-manager")]
    [Authorize]
    public class FileManagerController : ApiControllerBase
    {
        private readonly IFileManagerService _fileManagerService;
        private readonly ILoggingService _loggingService;

        public FileManagerController(IFileManagerService fileManagerService, ILoggingService loggingService)
        {
            _fileManagerService = fileManagerService;
            _loggingService = loggingService;
        }

        private Guid? GetUserIdFromToken()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();

            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return null; // Return null if token is missing or invalid
            }

            var authToken = authHeader.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            try
            {
                var jwtToken = handler.ReadJwtToken(authToken);
                var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

                return userIdClaim != null ? Guid.Parse(userIdClaim) : null;
            }
            catch
            {
                return null; // Return null if token is invalid
            }
        }

        [HttpPost("create-folder")]
        public async Task<IActionResult> CreateFolder([FromForm] CreateFolderRequest request)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }
            if (request == null || string.IsNullOrWhiteSpace(request.Name))
            {
                return BadRequest(new { meta = new { code = 0, message = "Invalid request, Folder name is required." } });
            }
            
            // If ParentFolderId is provided, it should not be empty
            if (request.ParentFolderId.HasValue && request.ParentFolderId.Value == Guid.Empty)
            {
                return BadRequest(new { meta = new { code = 0, message = "Invalid Parent Folder ID." } });
            }
            var response = await _fileManagerService.CreateFolderAsync(request , userId.Value);
            await _loggingService.LogAsync(
    "CreateFolder", TrackedEntity.Folder, response?.Id,
    null, null, userId.ToString(),
    "New folder created",
    $"Name: {request.Name}, ParentId: {request.ParentFolderId}"
);
            return response != null
                ? Ok(new { meta = new { code = 1, message = "Folder created successfully" }, data = response })
                : BadRequest(new { meta = new { code = 0, message = "Failed to create folder, Parent folder not found" } });
        }

        [HttpPost("upload-files")]
        public async Task<IActionResult> UploadFiles([FromForm] UploadFileRequest request)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }

            if (request.Files == null || request.Files.Count == 0)
            {
                await _loggingService.LogAsync("UploadFiles", TrackedEntity.File, null, null, null, userId.ToString(), "No files uploaded", "Request contained zero files");
                return BadRequest(new { meta = new { code = 0, message = "No files uploaded" } });
            }

            const long MaxFileSize = 100 * 1024 * 1024; // 100MB in bytes
            var oversizedFiles = request.Files.Where(f => f.Length > MaxFileSize).ToList();

            if (oversizedFiles.Any())
            {
                await _loggingService.LogAsync("UploadFilesFailed", TrackedEntity.File, null, null,null
            , userId.ToString(), "Request contains Oversized files", $"Oversized Files: {string.Join(", ", oversizedFiles.Select(f => $"{f.FileName} ({(f.Length / (1024 * 1024)):F2} MB)"))}");

                return BadRequest(new
                {
                    meta = new { code = 0, message = "No files were uploaded. Some files exceed the 100MB size limit." },
                    data = new
                    {
                        oversizedFiles = oversizedFiles.Select(f => new
                        {
                            FileName = f.FileName,
                            SizeInMB = (f.Length / (1024 * 1024)).ToString("F2")
                        })
                    }
                });
            }

            // Determine the target folder (assign root folder if none is provided)
            var folderId = request.FolderId;
            if (folderId == null || folderId == Guid.Empty)
            {
                var rootFolders = await _fileManagerService.GetAllFoldersWithFilesAsync(userId.Value) ?? new List<FolderResponse>(); ;

                // If no root folder exists, the system creates one automatically
                if (!rootFolders.Any())
                {
                    var rootFolder = await _fileManagerService.CreateRootFolderAsync();
                    folderId = rootFolder.Id;
                }
                else
                {
                    folderId = rootFolders.First().Id; // Use the existing root folder
                }
            }
            request.FolderId = folderId;
            var (uploadedFiles, failedFiles) = await _fileManagerService.UploadFilesAsync(request , userId.Value);
            await _loggingService.LogAsync(
    "UploadFiles", TrackedEntity.File, null,
    null, null, userId.ToString(),
    "Files uploaded",
    $"Uploaded: {uploadedFiles.Count}, Failed: {failedFiles.Count}, FolderId: {request.FolderId}"
);
            return Ok(new
            {
                meta = new { code = uploadedFiles.Any() ? 1 : 0, message = "File upload completed" },
                data = new
                {
                    uploadedFiles,
                    failedFiles
                } 
            });
        }
        [HttpGet("folders")]
        public async Task<IActionResult> GetFolders([FromQuery] Guid? folderId)
        {
            var userId = GetUserIdFromToken();
            if (userId == null)
            {
                await _loggingService.LogErrorAsync(
                    "Unauthorized folder access attempt",
                    "Invalid token",
                    "Anonymous"
                );
                return Unauthorized(new
                {
                    meta = new { code = 0, message = "Invalid or missing authorization token." }
                });
            }

            FolderResponse? folder;
            List<FolderPathItem>? path = null;

            if (folderId.HasValue)
            {
                await _loggingService.LogAsync(
                    "GetFolderById", TrackedEntity.Folder, folderId, null, null, userId.ToString(),
                    "Fetched folder by ID", $"FolderId: {folderId}"
                );

                folder = await _fileManagerService.GetFolderByIdAsync(folderId.Value);
                if (folder == null)
                {
                    return NotFound(new
                    {
                        meta = new { code = 0, message = "Folder not found" }
                    });
                }

                folder = await _fileManagerService.GetFolderByIdAsync(folderId.Value);
                if (folder == null)
                {
                    return NotFound(new
                    {
                        meta = new { code = 0, message = "Folder not found" }
                    });
                }

                path = await _fileManagerService.GetFolderPathAsync(folderId.Value);
                folder.path = path;

                return Ok(new
                {
                    meta = new { code = 1, message = "Folder retrieved successfully" },
                    data = folder,
                    
                });
            }
            else
            {
                var rootFolders = await _fileManagerService.GetAllFoldersWithFilesAsync(userId.Value);

                if (!rootFolders.Any())
                {
                    folder = await _fileManagerService.CreateRootFolderAsync();
                }
                else
                {
                    folder = rootFolders.First(); // Just take the first one as root
                }

                await _loggingService.LogAsync(
                    "GetRootFolder", TrackedEntity.Folder, folder?.Id, null, null, userId.ToString(),
                    "Fetched root folder"
                );
                path = new List<FolderPathItem>
        {
            new FolderPathItem(folder.Id, folder.Name)
        };
                folder.path = path;
                return Ok(new
                {
                    meta = new { code = 1, message = "Root folder retrieved successfully" },
                    data = folder,
                });
            }
        }

        [HttpGet("file/{fileId}")]
        public async Task<IActionResult> GetFileById(Guid fileId)
        {
            var response = await _fileManagerService.GetFileByIdAsync(fileId);
            var path = await _fileManagerService.GetFilePathAsync(fileId); // Returns List<FolderPathItem>
            await _loggingService.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString(), "Fetched file by ID", $"FileId: {fileId}");
            response.path=path;
            return response != null
                ? Ok(new { meta = new { code = 1, message = "File retrieved successfully" }, data = response})
                : NotFound(new { meta = new { code = 0, message = "File not found" } });
        }

        [HttpGet("file/download/{fileId}")]
        public async Task<IActionResult> DownloadFile(Guid fileId)
        {
            var (fileStream, fileName, contentType) = await _fileManagerService.DownloadFileAsync(fileId);
            if (fileStream == null)
            {
                return NotFound(new { meta = new { code = 0, message = "File not found or deleted" } });
            }
            await _loggingService.LogAsync("DownloadFile", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString(), "File downloaded", $"FileName: {fileName}");
            return File(fileStream, contentType ?? "application/octet-stream", fileName);
        }

        [HttpDelete("file/{fileId}")]
        public async Task<IActionResult> DeleteFile(Guid fileId)
        {
            var result = await _fileManagerService.DeleteFileAsync(fileId);
            if (result)
            {
                await _loggingService.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString(), "File deleted", $"FileId: {fileId}");
            }
            return result
                ? Ok(new { meta = new { code = 1, message = "File deleted successfully" } })
                : NotFound(new { meta = new { code = 0, message = "File not found or could not be deleted" } });
        }

        [HttpDelete("folder/{folderId}")]
        public async Task<IActionResult> DeleteFolder(Guid folderId)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }
            var result = await _fileManagerService.DeleteFolderAsync(folderId);
            if (result)
            {
                await _loggingService.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString(), "Folder deleted", $"FolderId: {folderId}");
            }
            return result
                ? Ok(new { meta = new { code = 1, message = "Folder deleted successfully" } })
                : BadRequest(new { meta = new { code = 0, message = "Folder not found or has subfolders, cannot be deleted" } });
        }
    }
}
