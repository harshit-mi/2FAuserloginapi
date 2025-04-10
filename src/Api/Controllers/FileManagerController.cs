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
using Microsoft.EntityFrameworkCore;

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
                return BadRequest(new { meta = new { code = 2, message = "No files uploaded" } });
            }

            const long MaxFileSize = 100 * 1024 * 1024;
            var uploadedFiles = new List<FileResponse>();
            var failedFiles = new List<object>();

            // Determine the folder ID
            var folderId = request.FolderId;
            if (folderId == null || folderId == Guid.Empty)
            {
                var rootFolders = await _fileManagerService.GetAllFoldersWithFilesAsync(userId.Value) ?? new List<FolderResponse>();
                if (!rootFolders.Any())
                {
                    var rootFolder = await _fileManagerService.CreateRootFolderAsync();
                    folderId = rootFolder.Id;
                }
                else
                {
                    folderId = rootFolders.First().Id;
                }
            }

            var validFileItems = new List<FileUploadItem>();

            foreach (var fileItem in request.Files)
            {
                if (fileItem.File == null || fileItem.File.Length == 0)
                {
                    failedFiles.Add(new
                    {
                        FileId = fileItem.FileId,
                        FileName = "[null]",
                        Reason = "File is missing or empty",
                        IsAllowRetry = false
                    });

                    await _loggingService.LogAsync(
                        "UploadFileSkipped",
                        TrackedEntity.File,
                        null, null, null, userId.ToString(),
                        "File skipped due to being null or empty",
                        $"FileId: {fileItem.FileId}"
                    );

                    continue;
                }

                if (fileItem.File.Length > MaxFileSize)
                {
                    failedFiles.Add(new
                    {
                        FileId = fileItem.FileId,
                        FileName = fileItem.File.FileName,
                        Reason = "File size exceeds 100MB limit",
                        SizeInMB = (fileItem.File.Length / (1024 * 1024)).ToString("F2"),
                        IsAllowRetry = false
                    });

                    await _loggingService.LogAsync(
                        "UploadFileSkipped",
                        TrackedEntity.File,
                        null, null, null, userId.ToString(),
                        "File skipped due to size limit",
                        $"File: {fileItem.File.FileName}, Size: {(fileItem.File.Length / (1024 * 1024)):F2} MB"
                    );

                    continue;
                }

                validFileItems.Add(new FileUploadItem
                {
                    FileId = fileItem.FileId != Guid.Empty ? fileItem.FileId : Guid.NewGuid(),
                    File = fileItem.File,
                    //temperory-test
                    AllowRetry = fileItem.AllowRetry
                });
            }

            if (validFileItems.Any())
            {
                var uploadRequest = new UploadFileRequest
                {
                    FolderId = folderId,
                    Files = validFileItems
                };

                try
                {
                    var (uploaded, failed) = await _fileManagerService.UploadFilesAsync(uploadRequest, userId.Value);

                    if (uploaded.Any())
                        uploadedFiles.AddRange(uploaded);

                    if (failed.Any())
                        failedFiles.AddRange(failed);
                }
                catch (Exception ex)
                {
                    await _loggingService.LogErrorAsync("Upload failed", ex.Message, userId.ToString());

                    return StatusCode(500, new
                    {
                        meta = new { code = 0, message = "Upload failed. A technical error occurred. Please try again later." }
                    });
                }
            }

            await _loggingService.LogAsync(
                "UploadFiles",
                TrackedEntity.File,
                null, null, null, userId.ToString(),
                "Upload attempt finished",
                $"Uploaded: {uploadedFiles.Count}, Failed: {failedFiles.Count}, FolderId: {folderId}"
            );

            var uploadedCount = uploadedFiles.Count;
            var failedCount = failedFiles.Count;

            string message = uploadedCount switch
            {
                > 0 when failedCount == 0 => "All files uploaded successfully.",
                > 0 when failedCount > 0 => $"{uploadedCount} file(s) uploaded, {failedCount} file(s) failed.",
                _ => "All file uploads failed."
            };

            int code = uploadedCount switch
            {
                > 0 when failedCount == 0 => 1,  // All success
                > 0 when failedCount > 0 => 0,   // Partial success
                _ => 2                           // All failed
            };

            return Ok(new
            {
                meta = new { code, message },
                data = new
                {
                    uploadedFiles,
                    failedFiles
                }
            });
        }


        [HttpPost("retry-upload/{retryKey}")]
        public async Task<IActionResult> RetryUploadByKey(Guid retryKey)
        {
            var userId = GetUserIdFromToken();
            if (userId == null)
                return Unauthorized(new { meta = new { code = 0, message = "Invalid token" } });

            if (retryKey == Guid.Empty)
                return BadRequest(new { meta = new { code = 0, message = "Invalid retry key" } });

            var (success, error) = await _fileManagerService.RetryUploadByKeyAsync(retryKey, userId.Value);

            if (success)
                return Ok(new { meta = new { code = 1, message = "File upload retried successfully" } });

            return BadRequest(new
            {
                meta = new { code = 0, message = "Retry failed", RetryKey = retryKey, error }
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
            if (response != null)
            {
                var path = await _fileManagerService.GetFilePathAsync(fileId); // Returns List<FolderPathItem>
                await _loggingService.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, GetUserIdFromToken()?.ToString(), "Fetched file by ID", $"FileId: {fileId}");
                response.path = path;
            }
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

        [HttpDelete("{type}/{id}")]
        public async Task<IActionResult> DeleteItem(string type, Guid id)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized deletion attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }

            bool result = false;
            string message = "";
            string logAction = "";
            TrackedEntity? entity = null;

            switch (type.ToLower())
            {
                case "file":
                    result = await _fileManagerService.DeleteFileAsync(id);
                    logAction = "DeleteFile";
                    entity = TrackedEntity.File;
                    message = result ? "File deleted successfully" : "File not found or could not be deleted";
                    break;

                case "folder":
                    result = await _fileManagerService.DeleteFolderAsync(id);
                    logAction = "DeleteFolder";
                    entity = TrackedEntity.Folder;
                    message = result ? "Folder and its contents deleted successfully" : "Folder not found or could not be deleted";
                    break;

                default:
                    return BadRequest(new { meta = new { code = 0, message = "Invalid type. Allowed values are 'file' or 'folder'." } });
            }

            if (result)
            {
                await _loggingService.LogAsync(
                    logAction,
                    entity.Value,
                    id,
                    null,
                    null,
                    userId.ToString(),
                    $"{type.First().ToString().ToUpper() + type.Substring(1)} deleted",
                    $"{type}Id: {id}"
                );
            }

            return result
                ? Ok(new { meta = new { code = 1, message } })
                : BadRequest(new { meta = new { code = 0, message } });
        }

        [HttpPut("{type}/{id}/rename")]
        public async Task<IActionResult> RenameItem(string type, Guid id, [FromBody] RenameRequest request)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized rename attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }

            if (string.IsNullOrWhiteSpace(request.NewName))
            {
                return BadRequest(new { meta = new { code = 0, message = "New name must not be empty." } });
            }

            bool result = false;
            string message = "";
            string logAction = "";
            TrackedEntity? entity = null;

            switch (type.ToLower())
            {
                case "file":
                    result = await _fileManagerService.RenameFileAsync(id, request.NewName);
                    logAction = "RenameFile";
                    entity = TrackedEntity.File;
                    message = result ? "File renamed successfully" : "File not found or rename failed";
                    break;

                case "folder":
                    result = await _fileManagerService.RenameFolderAsync(id, request.NewName);
                    logAction = "RenameFolder";
                    entity = TrackedEntity.Folder;
                    message = result ? "Folder renamed successfully" : "Folder not found or rename failed";
                    break;

                default:
                    return BadRequest(new { meta = new { code = 0, message = "Invalid type. Allowed values are 'file' or 'folder'." } });
            }

            if (result)
            {
                await _loggingService.LogAsync(
                    logAction,
                    entity.Value,
                    id,
                    null,
                    null,
                    userId.ToString(),
                    $"{type.First().ToString().ToUpper() + type.Substring(1)} renamed",
                    $"NewName: {request.NewName}"
                );
            }

            return result
                ? Ok(new { meta = new { code = 1, message } })
                : BadRequest(new { meta = new { code = 0, message } });
        }


        [HttpGet("globalsearch")]
        public async Task<IActionResult> GlobalSearch([FromQuery] string? query)
        {
            var userId = GetUserIdFromToken();

            if (userId == null)
            {
                await _loggingService.LogErrorAsync("Unauthorized global search attempt", "Invalid token", "Anonymous");
                return Unauthorized(new { meta = new { code = 0, message = "Invalid or missing authorization token." } });
            }

            if (string.IsNullOrWhiteSpace(query))
            {
                return BadRequest(new { meta = new { code = 0, message = "Search query must not be empty." } });
            }

            var result = await _fileManagerService.GlobalSearchAsync(query.Trim(), userId.Value);

            return Ok(new
            {
                meta = new { code = 1, message = "Global search completed successfully." },
                data = result
            });
        }
    }
}
