using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Ecos.Api.Controllers.Base;
using Ecos.Application.DTOs.Request;
using Ecos.Application.Services;
using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ecos.Api.Controllers
{
    [Route("[controller]")]
    [Authorize]
    public class FileManagerController : ApiControllerBase
    {
        private readonly IFileManagerService _fileManagerService;
        private readonly LoggingService _loggingService;

        public FileManagerController(IFileManagerService fileManagerService, LoggingService loggingService)
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
        public async Task<IActionResult> CreateFolder([FromBody] CreateFolderRequest request)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }
            var response = await _fileManagerService.CreateFolderAsync(request , userId.Value);
            await _loggingService.LogAsync("CreateFolder", TrackedEntity.Folder, response?.Id, null, response, userId.ToString());
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
                await _loggingService.LogAsync("UploadFiles", TrackedEntity.File, null, null,
            new { Message = "No files uploaded" }, userId.ToString());
                return BadRequest(new { meta = new { code = 0, message = "No files uploaded" } });
            }

            const long MaxFileSize = 100 * 1024 * 1024; // 100MB in bytes
            var oversizedFiles = request.Files.Where(f => f.Length > MaxFileSize).ToList();

            if (oversizedFiles.Any())
            {
                await _loggingService.LogAsync("UploadFilesFailed", TrackedEntity.File, null, null,
            new { Reason = "Oversized files", Files = oversizedFiles.ToArray() }, userId.ToString());

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

            var (uploadedFiles, failedFiles) = await _fileManagerService.UploadFilesAsync(request , userId.Value);
            await _loggingService.LogAsync("UploadFiles", TrackedEntity.File, null, null, new { uploadedFiles, failedFiles }, userId.ToString());
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


        [HttpGet("Get-folders")]
        public async Task<IActionResult> GetAllFoldersWithFiles()
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }

            var response = await _fileManagerService.GetAllFoldersWithFilesAsync(userId.Value);
            await _loggingService.LogAsync("GetAllFolders", TrackedEntity.Folder, null, null, null, userId.ToString());
            return Ok(new { meta = new { code = 1, message = "Folders retrieved successfully" }, data = response });
        }

        [HttpGet("folder/{folderId}")]
        public async Task<IActionResult> GetFolderById(Guid folderId)
        {
            var response = await _fileManagerService.GetFolderByIdAsync(folderId);
            await _loggingService.LogAsync("GetFolderById", TrackedEntity.Folder, folderId, null, response, GetUserIdFromToken()?.ToString());
            return response != null
                ? Ok(new { meta = new { code = 1, message = "Folder retrieved successfully" }, data = response })
                : NotFound(new { meta = new { code = 0, message = "Folder not found" } });
        }

        [HttpGet("file/{fileId}")]
        public async Task<IActionResult> GetFileById(Guid fileId)
        {
            var response = await _fileManagerService.GetFileByIdAsync(fileId);
            await _loggingService.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString());
            return response != null
                ? Ok(new { meta = new { code = 1, message = "File retrieved successfully" }, data = response })
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
            await _loggingService.LogAsync("DownloadFile", TrackedEntity.File, fileId, null, new { fileName }, GetUserIdFromToken()?.ToString());
            return File(fileStream, contentType ?? "application/octet-stream", fileName);
        }

        [HttpDelete("file/{fileId}")]
        public async Task<IActionResult> DeleteFile(Guid fileId)
        {
            var result = await _fileManagerService.DeleteFileAsync(fileId);
            if (result)
            {
                await _loggingService.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString());
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
                await _loggingService.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString());
            }
            return result
                ? Ok(new { meta = new { code = 1, message = "Folder deleted successfully" } })
                : BadRequest(new { meta = new { code = 0, message = "Folder not found or has subfolders, cannot be deleted" } });
        }
    }
}
