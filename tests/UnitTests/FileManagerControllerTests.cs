using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Ecos.Api.Controllers;
using Ecos.Application.DTOs.Request;
using Ecos.Application.DTOs.Response;
using Ecos.Application.Services;
using Ecos.Domain.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Newtonsoft.Json;

namespace Ecos.Tests.Controllers
{
    public class FileManagerControllerTests
    {
        private readonly Mock<IFileManagerService> _fileManagerServiceMock;
        private readonly Mock<ILoggingService> _loggingServiceMock;
        private readonly FileManagerController _controller;

        public FileManagerControllerTests()
        {
            _fileManagerServiceMock = new Mock<IFileManagerService>();
            _loggingServiceMock = new Mock<ILoggingService>();
            _controller = new FileManagerController(_fileManagerServiceMock.Object, _loggingServiceMock.Object);
        }

        private void SetUser(Guid userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisIsASecretKeyForTestingOnly!!"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim("sub", userId.ToString())
        }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Headers["Authorization"] = $"Bearer {tokenString}";
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };
        }

        #region create folder
        [Fact]
        public async Task CreateFolder_ReturnsUnauthorized_WhenAuthorizationHeaderIsMissing()
        {
            // Arrange
            var request = new CreateFolderRequest
            {
                Name = "NewFolder",
                ParentFolderId = Guid.NewGuid()
            };

            // No Authorization header set in HttpContext
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task CreateFolder_ReturnsUnauthorized_WhenTokenIsInvalid()
        {
            // Arrange
            var request = new CreateFolderRequest
            {
                Name = "NewFolder",
                ParentFolderId = Guid.NewGuid()
            };

            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = "Bearer this-is-not-a-valid-jwt";

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task CreateFolder_ValidRequest_ReturnsOk()
        {
            // Arrange
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new CreateFolderRequest
            {
                Name = "NewFolder",
                ParentFolderId = Guid.NewGuid()
            };

            var folderResponse = new FolderResponse(
                Guid.NewGuid(),
                "NewFolder",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                null,
                null,
                DateTime.UtcNow,
                null,0
            );

            _fileManagerServiceMock
                .Setup(x => x.CreateFolderAsync(request, userId))
                .ReturnsAsync(folderResponse);

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<OkObjectResult>(result);
            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

            Assert.NotNull(response);
            Assert.NotNull(response.meta);
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("Folder created successfully", (string)response.meta.message);

            Assert.NotNull(response.data);
        }


        [Fact]
        public async Task CreateFolder_ReturnsBadRequest_WhenFolderNameIsMissing()
        {
            // Arrange
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new CreateFolderRequest
            {
                Name = "", // Empty name
                ParentFolderId = Guid.NewGuid()
            };

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Invalid request, Folder name is required.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task CreateFolder_ReturnsBadRequest_WhenParentFolderIdIsEmptyGuid()
        {
            // Arrange
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new CreateFolderRequest
            {
                Name = "NewFolder",
                ParentFolderId = Guid.Empty // Will trigger the Guid.Empty check
            };

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Invalid Parent Folder ID.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task CreateFolder_ReturnsBadRequest_WhenParentFolderNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new CreateFolderRequest
            {
                Name = "NewFolder",
                ParentFolderId = Guid.NewGuid()
            };

            _fileManagerServiceMock
                .Setup(x => x.CreateFolderAsync(request, userId))
                .ReturnsAsync((FolderResponse)null); // Simulate not found

            // Act
            var result = await _controller.CreateFolder(request);

            // Assert
            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal("Failed to create folder, Parent folder not found", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        #endregion

        #region Upload File
        private FileUploadItem GetMockFileItem(string fileName, int sizeInMB, Guid? fileId = null)
        {
            var content = new byte[sizeInMB * 1024 * 1024];
            var stream = new MemoryStream(content);
            var formFile = new FormFile(stream, 0, content.Length, "file", fileName)
            {
                Headers = new HeaderDictionary(),
                ContentType = "application/octet-stream"
            };

            return new FileUploadItem
            {
                FileId = fileId ?? Guid.NewGuid(),
                File = formFile,
                //temperory-test
                AllowRetry = true
            };
        }

        [Fact]
        public async Task UploadFiles_MissingToken_ReturnsUnauthorized()
        {
            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { GetMockFileItem("test.txt", 10) }
            };

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No user/claims set
            };

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
        }

        [Fact]
        public async Task UploadFiles_NoFiles_ReturnsBadRequest()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new UploadFileRequest(); // Files is null

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(2, (int)response.meta.code);
            Assert.Equal("No files uploaded", (string)response.meta.message);
        }

        [Fact]
        public async Task UploadFiles_FileTooLarge_ReturnsPartialFailureResponse()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var oversizedFile = GetMockFileItem("bigfile.zip", 101);

            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { oversizedFile }
            };

            _fileManagerServiceMock
                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
                .ReturnsAsync(new List<FolderResponse>
                {
            new FolderResponse(
                Guid.NewGuid(),
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem>(),
                "Admin",
                DateTime.UtcNow,
                "0 B", 0)
                });

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(2, (int)response.meta.code); // Indicates all failed
            Assert.Equal("All file uploads failed.", (string)response.meta.message);
            Assert.NotNull(response.data.failedFiles);
            Assert.Single(response.data.failedFiles);
            Assert.Equal("bigfile.zip", (string)response.data.failedFiles[0].FileName);
            Assert.Contains("exceeds", (string)response.data.failedFiles[0].Reason.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task UploadFiles_InvalidFolderIdProvided_ReturnsBadRequest()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var invalidFolderId = Guid.NewGuid(); // Simulate a non-existent folder ID

            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { GetMockFileItem("file.txt", 1) },
                FolderId = invalidFolderId
            };

            // Only return one root folder that doesn't match the invalidFolderId
            _fileManagerServiceMock
                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
                .ReturnsAsync(new List<FolderResponse>
                {
            new FolderResponse(
                Guid.NewGuid(), // Different ID than invalidFolderId
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem>(),
                "Admin",
                DateTime.UtcNow,
                "0 B", 0)
                });

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(500, actionResult.StatusCode);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Upload failed. A technical error occurred. Please try again later.", (string)response.meta.message);
        }

        [Fact]
        public async Task UploadFiles_UploadServiceThrows_ReturnsInternalServerError()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { GetMockFileItem("file.jpg", 1) }
            };

            _fileManagerServiceMock
               .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
               .ReturnsAsync(new List<FolderResponse> {
           new FolderResponse(
               Guid.NewGuid(),
               "Root",
               new List<FileResponse>(),
               new List<FolderResponse>(),
               new List<FolderPathItem>(),
               "Admin",
               DateTime.UtcNow,
               "0 B", 0)
               });

            _fileManagerServiceMock
                .Setup(x => x.UploadFilesAsync(It.IsAny<UploadFileRequest>(), userId))
                .ThrowsAsync(new Exception("Simulated internal error"));

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(500, actionResult.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));
            Assert.Equal("Upload failed. A technical error occurred. Please try again later.", (string)response.meta.message);
            Assert.Equal(0, (int)response.meta.code);
        }

        [Fact]
        public async Task UploadFiles_ValidFiles_ReturnsOk()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var fileItem = GetMockFileItem("image.png", 1);
            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { fileItem }
            };

            _fileManagerServiceMock
                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
                .ReturnsAsync(new List<FolderResponse> {
            new FolderResponse(
                Guid.NewGuid(),
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem>(),
                "Admin",
                DateTime.UtcNow,
                "0 B", 0)
                });

            _fileManagerServiceMock
                .Setup(x => x.UploadFilesAsync(It.IsAny<UploadFileRequest>(), userId))
                .ReturnsAsync((
                    new List<FileResponse>
                    {
                new FileResponse(
                    Guid.NewGuid(),
                    "image.png",
                    "https://storage.com/blob/image.png",
                    new List<FolderPathItem> { new FolderPathItem(Guid.NewGuid(), "Root") },
                    "1 MB",
                    "John Doe",
                    DateTime.UtcNow)
                    },
                    new List<object>()
                ));

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("All files uploaded successfully.", (string)response.meta.message);

            Assert.NotNull(response.data.uploadedFiles);
            Assert.Single(response.data.uploadedFiles);
            Assert.Equal("file", (string)response.data.uploadedFiles[0].Type);
            Assert.Equal("png", (string)response.data.uploadedFiles[0].Extension);
            Assert.NotNull(response.data.uploadedFiles[0].path);
            Assert.Empty(response.data.failedFiles);
        }

        [Fact]
        public async Task UploadFiles_SomeFilesFail_ReturnsPartialSuccess()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var file1 = GetMockFileItem("doc1.pdf", 1);
            var file2 = GetMockFileItem("doc2.pdf", 1);

            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { file1, file2 },
                FolderId = Guid.NewGuid()
            };

            _fileManagerServiceMock
                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
                .ReturnsAsync(new List<FolderResponse> {
            new FolderResponse(
                Guid.NewGuid(),
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem>(),
                "Admin",
                DateTime.UtcNow,
                "0 B", 0)
                });

            _fileManagerServiceMock
                .Setup(x => x.UploadFilesAsync(It.IsAny<UploadFileRequest>(), userId))
                .ReturnsAsync((
                    new List<FileResponse>
                    {
                new FileResponse(
                    Guid.NewGuid(),
                    "doc1.pdf",
                    "https://storage.blob/core/doc1.pdf",
                    new List<FolderPathItem> { new FolderPathItem(Guid.NewGuid(), "Docs") },
                    "512 KB",
                    "Jane Doe",
                    DateTime.UtcNow)
                    },
                    new List<object>
                    {
                new
                {
                    FileId = file2.FileId,
                    FileName = "doc2.pdf",
                    Reason = "Simulated failure",
                    IsAllowRetry = true
                }
                    }
                ));

            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("1 file(s) uploaded, 1 file(s) failed.", (string)response.meta.message);

            Assert.Single(response.data.uploadedFiles);
            Assert.Equal("file", (string)response.data.uploadedFiles[0].Type);
            Assert.Equal("pdf", (string)response.data.uploadedFiles[0].Extension);
            Assert.NotNull(response.data.uploadedFiles[0].path);

            Assert.Single(response.data.failedFiles);
            Assert.Equal("doc2.pdf", (string)response.data.failedFiles[0].FileName);
            Assert.Equal("Simulated failure", (string)response.data.failedFiles[0].Reason);
            Assert.True((bool)response.data.failedFiles[0].IsAllowRetry);
        }

        [Fact]
        public async Task UploadFiles_OversizedFile_ReturnsAllFailed()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var oversizedItem = GetMockFileItem("huge.mp4", 105);
            var request = new UploadFileRequest
            {
                Files = new List<FileUploadItem> { oversizedItem }
            };
            _fileManagerServiceMock
                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
                .ReturnsAsync(new List<FolderResponse> {
            new FolderResponse(
                Guid.NewGuid(),
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem>(),
                "Admin",
                DateTime.UtcNow,
                "0 B", 0)
                });
            var result = await _controller.UploadFiles(request);

            var actionResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

            Assert.Equal(2, (int)response.meta.code);
            Assert.Equal("All file uploads failed.", (string)response.meta.message);
            Assert.Empty(response.data.uploadedFiles);
            Assert.Single(response.data.failedFiles);
        }

        #endregion

        #region Get Folder

        [Fact]
        public async Task GetAllFoldersWithFiles_ValidUser_ReturnsOk()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var folder = new FolderResponse(
                Guid.NewGuid(),
                "Folder1",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem> { new FolderPathItem(Guid.NewGuid(), "Folder1") },
                "testuser",
                DateTime.UtcNow,
                "0 Bytes",0
            );

            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(new List<FolderResponse> { folder });

            var result = await _controller.GetFolders(null) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("Root folder retrieved successfully", (string)response.meta.message);
        }
        [Fact]
        public async Task GetFolderById_FolderExists_ReturnsOk()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var folderId = Guid.NewGuid();
            var path = new List<FolderPathItem> { new FolderPathItem(folderId, "Folder1") };

            var folderResponse = new FolderResponse(
                folderId,
                "Folder1",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                path,
                "testuser",
                DateTime.UtcNow,
                "0 Bytes",0
            );

            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync(folderResponse);
            _fileManagerServiceMock.Setup(x => x.GetFolderPathAsync(folderId)).ReturnsAsync(path);

            var result = await _controller.GetFolders(folderId) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("Folder retrieved successfully", (string)response.meta.message);
            Assert.Equal("Folder1", (string)response.data.Name.ToString());
        }

        [Fact]
        public async Task GetFolderById_FolderNotFound_ReturnsNotFound()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var folderId = Guid.NewGuid();
            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync((FolderResponse?)null);

            var result = await _controller.GetFolders(folderId) as NotFoundObjectResult;

            Assert.NotNull(result);
            Assert.Equal(404, result.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Folder not found", (string)response.meta.message);
        }

        [Fact]
        public async Task GetAllFolders_NoFoldersExist_CreatesRootFolder()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var rootFolder = new FolderResponse(
                Guid.NewGuid(),
                "Root",
                new List<FileResponse>(),
                new List<FolderResponse>(),
                new List<FolderPathItem> { new FolderPathItem(Guid.NewGuid(), "Root") },
                "system",
                DateTime.UtcNow,
                "0 Bytes",0
            );

            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(new List<FolderResponse>());
            _fileManagerServiceMock.Setup(x => x.CreateRootFolderAsync()).ReturnsAsync(rootFolder);

            var result = await _controller.GetFolders(null) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("Root folder retrieved successfully", (string)response.meta.message);
            Assert.Equal("Root", (string)response.data.Name.ToString());
        }

        [Fact]
        public async Task GetFolderById_ValidRequest_LogsAction()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var folderId = Guid.NewGuid();
            var path = new List<FolderPathItem>();
            var folderResponse = new FolderResponse(
                folderId, "TestFolder",
                new List<FileResponse>(), new List<FolderResponse>(),
                path, "testuser", DateTime.UtcNow, "0 Bytes",0
            );

            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync(folderResponse);
            _fileManagerServiceMock.Setup(x => x.GetFolderPathAsync(folderId)).ReturnsAsync(path);

            var result = await _controller.GetFolders(folderId) as OkObjectResult;

            Assert.NotNull(result);
            _loggingServiceMock.Verify(x =>
                x.LogAsync("GetFolderById", TrackedEntity.Folder, folderId, null, null, userId.ToString(), "Fetched folder by ID", $"FolderId: {folderId}"),
                Times.Once);
        }

        [Fact]
        public async Task GetFolderById_ResponseDataIsCorrect()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var folderId = Guid.NewGuid();
            var fileId = Guid.NewGuid();
            var path = new List<FolderPathItem>();

            var fileResponse = new FileResponse(fileId, "myfile.txt", "url", path, "10 KB", "uploader", DateTime.UtcNow);

            var folderResponse = new FolderResponse(
                folderId,
                "MyFolder",
                new List<FileResponse> { fileResponse },
                new List<FolderResponse>(),
                path,
                "user",
                DateTime.UtcNow,
                "10 KB",0
            );

            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync(folderResponse);
            _fileManagerServiceMock.Setup(x => x.GetFolderPathAsync(folderId)).ReturnsAsync(path);

            var result = await _controller.GetFolders(folderId) as OkObjectResult;

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal("MyFolder", (string)response.data.Name.ToString());
            Assert.Single(response.data.Files);
            Assert.Equal("myfile.txt", (string)response.data.Files[0].Name.ToString());
        }


        [Fact]
        public async Task GetAllFoldersWithSubfoldersAndFiles_ReturnsNestedStructure()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var subFolder = new FolderResponse(Guid.NewGuid(), "Sub", new List<FileResponse>(), new List<FolderResponse>(), new List<FolderPathItem>(), "user", DateTime.UtcNow, "0 Bytes",0);
            var rootFolder = new FolderResponse(Guid.NewGuid(), "Root", new List<FileResponse>(), new List<FolderResponse> { subFolder }, new List<FolderPathItem>(), "user", DateTime.UtcNow, "0 Bytes",0);

            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(new List<FolderResponse> { rootFolder });

            var result = await _controller.GetFolders(null) as OkObjectResult;

            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal("Root", (string)response.data.Name.ToString());
            Assert.Single(response.data.SubFolders);
            Assert.Equal("Sub", (string)response.data.SubFolders[0].Name.ToString());
        }

        #endregion

        #region File
        [Fact]
        public async Task GetFileById_FileExists_ReturnsOk()
        {
            var fileId = Guid.NewGuid();
            var file = new FileResponse(fileId, "file.txt", "blob-url", null, null, null, DateTime.UtcNow);

            _fileManagerServiceMock.Setup(x => x.GetFileByIdAsync(fileId)).ReturnsAsync(file);

            var context = new DefaultHttpContext();

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            var result = await _controller.GetFileById(fileId) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("File retrieved successfully", (string)response.meta.message);
            //_loggingServiceMock.Verify(x => x.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Once);
        }

        [Fact]
        public async Task GetFileById_FileNotFound_ReturnsNotFound()
        {
            var fileId = Guid.NewGuid();
            _fileManagerServiceMock.Setup(x => x.GetFileByIdAsync(fileId)).ReturnsAsync((FileResponse)null);

            var context = new DefaultHttpContext();

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            var result = await _controller.GetFileById(fileId) as NotFoundObjectResult;

            Assert.NotNull(result);
            Assert.Equal(404, result.StatusCode);
            //_loggingServiceMock.Verify(x => x.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Once);
        }

        #endregion

        #region DownloadFile

        [Fact]
        public async Task DownloadFile_FileExists_ReturnsFile()
        {
            var fileId = Guid.NewGuid();
            var fileName = "test.txt";
            var fileStream = new MemoryStream(Encoding.UTF8.GetBytes("Test file content"));
            var contentType = "text/plain";

            _fileManagerServiceMock.Setup(x => x.DownloadFileAsync(fileId))
                .ReturnsAsync((fileStream, fileName, contentType));

            var context = new DefaultHttpContext();

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            var result = await _controller.DownloadFile(fileId) as FileStreamResult;

            Assert.NotNull(result);
            Assert.Equal(contentType, result.ContentType);
            Assert.Equal(fileName, result.FileDownloadName);
            // _loggingServiceMock.Verify(x => x.LogAsync("DownloadFile", TrackedEntity.File, fileId, null,
            //  It.Is<object>(o => o.ToString().Contains(fileName)), null, "", ""), Times.Once);
        }

        [Fact]
        public async Task DownloadFile_FileNotFound_ReturnsNotFound()
        {
            var fileId = Guid.NewGuid();
            _fileManagerServiceMock.Setup(x => x.DownloadFileAsync(fileId))
                .ReturnsAsync((null as Stream, null, null));

            var result = await _controller.DownloadFile(fileId) as NotFoundObjectResult;

            Assert.NotNull(result);
            Assert.Equal(404, result.StatusCode);
        }
        #endregion

        #region Delete
        [Fact]
        public async Task DeleteItem_FileExists_ReturnsOk()
        {
            var fileId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock.Setup(x => x.DeleteFileAsync(fileId)).ReturnsAsync(true);

            var result = await _controller.DeleteItem("file", fileId) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, userId.ToString(), "File deleted", $"fileId: {fileId}"), Times.Once);
        }

        [Fact]
        public async Task DeleteItem_FileNotFound_ReturnsBadRequest()
        {
            var fileId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock.Setup(x => x.DeleteFileAsync(fileId)).ReturnsAsync(false);

            var result = await _controller.DeleteItem("file", fileId) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, userId.ToString(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }


        [Fact]
        public async Task DeleteItem_FolderExists_ReturnsOk()
        {
            var folderId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock.Setup(x => x.DeleteFolderAsync(folderId)).ReturnsAsync(true);

            var result = await _controller.DeleteItem("folder", folderId) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString(), "Folder deleted", $"folderId: {folderId}"), Times.Once);
        }

        [Fact]
        public async Task DeleteItem_FolderNotFound_ReturnsBadRequest()
        {
            var folderId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock.Setup(x => x.DeleteFolderAsync(folderId)).ReturnsAsync(false);

            var result = await _controller.DeleteItem("folder", folderId) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task DeleteItem_Unauthorized_ReturnsUnauthorized()
        {
            var id = Guid.NewGuid(); // File or folder ID

            var context = new DefaultHttpContext();
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            var result = await _controller.DeleteItem("file", id) as UnauthorizedObjectResult;

            Assert.NotNull(result);
            Assert.Equal(401, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogErrorAsync("Unauthorized deletion attempt", "Invalid token", "Anonymous"), Times.Once);
        }

        [Fact]
        public async Task DeleteItem_InvalidType_ReturnsBadRequest()
        {
            var id = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            var result = await _controller.DeleteItem("invalid", id) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);
        }

        #endregion


        #region GlobalSerch

        [Fact]
        public async Task GlobalSearch_ValidQuery_ReturnsOk()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var query = "test";
            var searchResult = new GlobalSearchResult
            {
                Files = new List<SearchItem>
        {
            new SearchItem { Id = Guid.NewGuid(), Name = "testfile.txt", Type = "File", CreatedAt = DateTime.UtcNow }
        },
                Folders = new List<SearchItem>
        {
            new SearchItem { Id = Guid.NewGuid(), Name = "testfolder", Type = "Folder", CreatedAt = DateTime.UtcNow }
        }
            };

            _fileManagerServiceMock.Setup(x => x.GlobalSearchAsync(query.Trim(), userId)).ReturnsAsync(searchResult);

            var result = await _controller.GlobalSearch(query) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);

            var data = result.Value.GetType().GetProperty("data")?.GetValue(result.Value);
            Assert.NotNull(data);

            _fileManagerServiceMock.Verify(x => x.GlobalSearchAsync(query.Trim(), userId), Times.Once);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("   ")]
        public async Task GlobalSearch_EmptyOrNullQuery_ReturnsBadRequest(string? query)
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var result = await _controller.GlobalSearch(query) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);

            _fileManagerServiceMock.Verify(x => x.GlobalSearchAsync(It.IsAny<string>(), It.IsAny<Guid>()), Times.Never);
        }

        [Fact]
        public async Task GlobalSearch_Unauthorized_ReturnsUnauthorized()
        {
            // No Authorization header set in HttpContext
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };

            // Don't call SetUser to simulate unauthorized request
            var result = await _controller.GlobalSearch("search") as UnauthorizedObjectResult;

            Assert.NotNull(result);
            Assert.Equal(401, result.StatusCode);

            _loggingServiceMock.Verify(x => x.LogErrorAsync("Unauthorized global search attempt", "Invalid token", "Anonymous"), Times.Once);
        }

        [Fact]
        public async Task GlobalSearch_QueryWithWhitespace_IsTrimmed()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var rawQuery = "   sample   ";
            var trimmedQuery = "sample";

            var dummyResult = new GlobalSearchResult();
            _fileManagerServiceMock.Setup(x => x.GlobalSearchAsync(trimmedQuery, userId)).ReturnsAsync(dummyResult);

            var result = await _controller.GlobalSearch(rawQuery) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _fileManagerServiceMock.Verify(x => x.GlobalSearchAsync(trimmedQuery, userId), Times.Once);
        }

        [Fact]
        public async Task GlobalSearch_NoResults_ReturnsEmptyResult()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var query = "nonexistent";
            var emptyResult = new GlobalSearchResult
            {
                Files = new List<SearchItem>(),
                Folders = new List<SearchItem>()
            };

            _fileManagerServiceMock.Setup(x => x.GlobalSearchAsync(query, userId)).ReturnsAsync(emptyResult);

            var result = await _controller.GlobalSearch(query) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _fileManagerServiceMock.Verify(x => x.GlobalSearchAsync(query, userId), Times.Once);
        }

        #endregion

        #region Rename

        [Fact]
        public async Task RenameItem_FileExists_ReturnsOk()
        {
            var fileId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new RenameRequest { NewName = "updated_filename.txt" };

            _fileManagerServiceMock.Setup(x => x.RenameFileAsync(fileId, request.NewName)).ReturnsAsync(true);

            var result = await _controller.RenameItem("file", fileId, request) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync(
                "RenameFile",
                TrackedEntity.File,
                fileId,
                null,
                null,
                userId.ToString(),
                "File renamed",
                $"NewName: {request.NewName}"
            ), Times.Once);
        }

        [Fact]
        public async Task RenameItem_FolderExists_ReturnsOk()
        {
            var folderId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new RenameRequest { NewName = "New Folder Name" };

            _fileManagerServiceMock.Setup(x => x.RenameFolderAsync(folderId, request.NewName)).ReturnsAsync(true);

            var result = await _controller.RenameItem("folder", folderId, request) as OkObjectResult;

            Assert.NotNull(result);
            Assert.Equal(200, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync(
                "RenameFolder",
                TrackedEntity.Folder,
                folderId,
                null,
                null,
                userId.ToString(),
                "Folder renamed",
                $"NewName: {request.NewName}"
            ), Times.Once);
        }

        [Fact]
        public async Task RenameItem_InvalidType_ReturnsBadRequest()
        {
            var id = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new RenameRequest { NewName = "DoesNotMatter" };

            var result = await _controller.RenameItem("invalid", id, request) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync(
                It.IsAny<string>(),
                It.IsAny<TrackedEntity>(),
                It.IsAny<Guid>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()
            ), Times.Never);
        }

        [Fact]
        public async Task RenameItem_EmptyNewName_ReturnsBadRequest()
        {
            var id = Guid.NewGuid();
            var userId = Guid.NewGuid();
            SetUser(userId);

            var request = new RenameRequest { NewName = "" };

            var result = await _controller.RenameItem("file", id, request) as BadRequestObjectResult;

            Assert.NotNull(result);
            Assert.Equal(400, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogAsync(
                It.IsAny<string>(),
                It.IsAny<TrackedEntity>(),
                It.IsAny<Guid>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()
            ), Times.Never);
        }

        [Fact]
        public async Task RenameItem_Unauthorized_ReturnsUnauthorized()
        {
            var id = Guid.NewGuid();
            var request = new RenameRequest { NewName = "SomeName" };

            var context = new DefaultHttpContext();
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = context
            };

            var result = await _controller.RenameItem("file", id, request) as UnauthorizedObjectResult;

            Assert.NotNull(result);
            Assert.Equal(401, result.StatusCode);
            _loggingServiceMock.Verify(x => x.LogErrorAsync("Unauthorized rename attempt", "Invalid token", "Anonymous"), Times.Once);
        }

        #endregion


        #region RetryUpload

        [Fact]
        public async Task RetryUploadByKey_ValidKey_UploadSucceeds_ReturnsOk()
        {
            var userId = Guid.NewGuid();
            var retryKey = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock
                .Setup(x => x.RetryUploadByKeyAsync(retryKey, userId))
                .ReturnsAsync((true, (string?)null));

            var result = await _controller.RetryUploadByKey(retryKey);

            var okResult = Assert.IsType<OkObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(okResult.Value));
            Assert.Equal(1, (int)response.meta.code);
            Assert.Equal("File upload retried successfully", (string)response.meta.message);
        }

        [Fact]
        public async Task RetryUploadByKey_KeyNotFound_ReturnsBadRequest()
        {
            var userId = Guid.NewGuid();
            var retryKey = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock
                .Setup(x => x.RetryUploadByKeyAsync(retryKey, userId))
                .ReturnsAsync((false, "Retry not found or already completed."));

            var result = await _controller.RetryUploadByKey(retryKey);

            var badResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(badResult.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Retry failed", (string)response.meta.message);
            Assert.Equal("Retry not found or already completed.", (string)response.meta.error);
        }

        [Fact]
        public async Task RetryUploadByKey_MissingToken_ReturnsUnauthorized()
        {
            var retryKey = Guid.NewGuid();

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No user context
            };

            var result = await _controller.RetryUploadByKey(retryKey);

            var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(unauthorized.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid token", (string)response.meta.message);
        }

        [Fact]
        public async Task RetryUploadByKey_EmptyRetryKey_ReturnsBadRequest()
        {
            var userId = Guid.NewGuid();
            SetUser(userId);

            var result = await _controller.RetryUploadByKey(Guid.Empty);

            var badResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(badResult.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Invalid retry key", (string)response.meta.message);
        }

        [Fact]
        public async Task RetryUploadByKey_UploadServiceThrows_ReturnsBadRequestWithError()
        {
            var userId = Guid.NewGuid();
            var retryKey = Guid.NewGuid();
            SetUser(userId);

            _fileManagerServiceMock
                .Setup(x => x.RetryUploadByKeyAsync(retryKey, userId))
                .ReturnsAsync((false, "Retry failed with error: Blob not available"));

            var result = await _controller.RetryUploadByKey(retryKey);

            var badResult = Assert.IsType<BadRequestObjectResult>(result);
            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(badResult.Value));
            Assert.Equal(0, (int)response.meta.code);
            Assert.Equal("Retry failed", (string)response.meta.message);
            Assert.Equal("Retry failed with error: Blob not available", (string)response.meta.error);
        }
        #endregion
    }
}
