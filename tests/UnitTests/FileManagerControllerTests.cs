//using System;
//using System.Collections.Generic;
//using System.IdentityModel.Tokens.Jwt;
//using System.IO;
//using System.Linq;
//using System.Security.Claims;
//using System.Text;
//using System.Threading.Tasks;
//using Ecos.Api.Controllers;
//using Ecos.Application.DTOs.Request;
//using Ecos.Application.DTOs.Response;
//using Ecos.Application.Services;
//using Ecos.Domain.Entities;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.IdentityModel.Tokens;
//using Moq;
//using Newtonsoft.Json;
//using Xunit;

//namespace Ecos.Tests.Controllers
//{
//    public class FileManagerControllerTests
//    {
//        private readonly Mock<IFileManagerService> _fileManagerServiceMock;
//        private readonly Mock<ILoggingService> _loggingServiceMock;
//        private readonly FileManagerController _controller;

//        public FileManagerControllerTests()
//        {
//            _fileManagerServiceMock = new Mock<IFileManagerService>();
//            _loggingServiceMock = new Mock<ILoggingService>();
//            _controller = new FileManagerController(_fileManagerServiceMock.Object, _loggingServiceMock.Object);
//        }

//        private void SetUser(Guid userId)
//        {
//            var tokenHandler = new JwtSecurityTokenHandler();
//            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisIsASecretKeyForTestingOnly!!"));

//            var tokenDescriptor = new SecurityTokenDescriptor
//            {
//                Subject = new ClaimsIdentity(new[]
//                {
//            new Claim("sub", userId.ToString())
//        }),
//                Expires = DateTime.UtcNow.AddMinutes(30),
//                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
//            };

//            var token = tokenHandler.CreateToken(tokenDescriptor);
//            var tokenString = tokenHandler.WriteToken(token);

//            var httpContext = new DefaultHttpContext();
//            httpContext.Request.Headers["Authorization"] = $"Bearer {tokenString}";
//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = httpContext
//            };
//        }

//        #region create folder
//        [Fact]
//        public async Task CreateFolder_ReturnsUnauthorized_WhenAuthorizationHeaderIsMissing()
//        {
//            // Arrange
//            var request = new CreateFolderRequest
//            {
//                Name = "NewFolder",
//                ParentFolderId = Guid.NewGuid()
//            };

//            // No Authorization header set in HttpContext
//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = new DefaultHttpContext()
//            };

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task CreateFolder_ReturnsUnauthorized_WhenTokenIsInvalid()
//        {
//            // Arrange
//            var request = new CreateFolderRequest
//            {
//                Name = "NewFolder",
//                ParentFolderId = Guid.NewGuid()
//            };

//            var context = new DefaultHttpContext();
//            context.Request.Headers["Authorization"] = "Bearer this-is-not-a-valid-jwt";

//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = context
//            };

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task CreateFolder_ValidRequest_ReturnsOk()
//        {
//            // Arrange
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var request = new CreateFolderRequest
//            {
//                Name = "NewFolder",
//                ParentFolderId = Guid.NewGuid()
//            };

//            var folderResponse = new FolderResponse(
//                Guid.NewGuid(),
//                "NewFolder",
//                new List<FileResponse>(),
//                new List<FolderResponse>(),
//                null
//            );

//            _fileManagerServiceMock
//                .Setup(x => x.CreateFolderAsync(request, userId))
//                .ReturnsAsync(folderResponse);

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<OkObjectResult>(result);
//            var jsonString = JsonConvert.SerializeObject(actionResult.Value);
//            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);

//            Assert.NotNull(response);
//            Assert.NotNull(response.meta);
//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("Folder created successfully", (string)response.meta.message);

//            Assert.NotNull(response.data);
//        }


//        [Fact]
//        public async Task CreateFolder_ReturnsBadRequest_WhenFolderNameIsMissing()
//        {
//            // Arrange
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var request = new CreateFolderRequest
//            {
//                Name = "", // Empty name
//                ParentFolderId = Guid.NewGuid()
//            };

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Invalid request, Folder name is required.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task CreateFolder_ReturnsBadRequest_WhenParentFolderIdIsEmptyGuid()
//        {
//            // Arrange
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var request = new CreateFolderRequest
//            {
//                Name = "NewFolder",
//                ParentFolderId = Guid.Empty // Will trigger the Guid.Empty check
//            };

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Invalid Parent Folder ID.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task CreateFolder_ReturnsBadRequest_WhenParentFolderNotFound()
//        {
//            // Arrange
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var request = new CreateFolderRequest
//            {
//                Name = "NewFolder",
//                ParentFolderId = Guid.NewGuid()
//            };

//            _fileManagerServiceMock
//                .Setup(x => x.CreateFolderAsync(request, userId))
//                .ReturnsAsync((FolderResponse)null); // Simulate not found

//            // Act
//            var result = await _controller.CreateFolder(request);

//            // Assert
//            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Failed to create folder, Parent folder not found", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        #endregion

//        #region Upload File

//        private IFormFile GetMockFile(string fileName, int sizeInMB)
//        {
//            var content = new byte[sizeInMB * 1024 * 1024];
//            var stream = new MemoryStream(content);
//            return new FormFile(stream, 0, content.Length, "file", fileName)
//            {
//                Headers = new HeaderDictionary(),
//                ContentType = "application/octet-stream"
//            };
//        }

//        [Fact]
//        public async Task UploadFiles_MissingToken_ReturnsUnauthorized()
//        {
//            // Arrange
//            var request = new UploadFileRequest
//            {
//                Files = new List<IFormFile> { GetMockFile("test.txt", 10) }
//            };

//            // No Authorization header set in HttpContext
//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = new DefaultHttpContext()
//            };
//            // Act
//            var result = await _controller.UploadFiles(request);

//            // Assert
//            var actionResult = Assert.IsType<UnauthorizedObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("Invalid or missing authorization token.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task UploadFiles_NoFiles_ReturnsBadRequest()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var request = new UploadFileRequest { Files = new List<IFormFile>() };

//            var result = await _controller.UploadFiles(request);

//            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("No files uploaded", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);
//        }

//        [Fact]
//        public async Task UploadFiles_ValidFiles_ReturnsOk()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var file = GetMockFile("image.png", 1); // 1MB
//            var request = new UploadFileRequest
//            {
//                Files = new List<IFormFile> { file }
//            };
//            _fileManagerServiceMock
//                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
//                .ReturnsAsync(new List<FolderResponse> { new FolderResponse(Guid.NewGuid(), "Root", new List<FileResponse>(), new List<FolderResponse>(), null) });

//            _fileManagerServiceMock
//                .Setup(x => x.UploadFilesAsync(request, userId))
//                .ReturnsAsync((new List<FileResponse>
//                {
//            new FileResponse(Guid.NewGuid(), "image.png", "https://storage.com/blob/image.png",null)
//                }, new List<string>()));

//            var result = await _controller.UploadFiles(request);

//            var actionResult = Assert.IsType<OkObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("File upload completed", (string)response.meta.message);
//            Assert.NotNull(response.data.uploadedFiles);
//            Assert.Single(response.data.uploadedFiles);
//            Assert.Empty(response.data.failedFiles);
//        }

//        [Fact]
//        public async Task UploadFiles_SomeFilesFail_ReturnsOkWithWarnings()
//        {
//            // Arrange: simulate a valid user
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var file1 = GetMockFile("doc1.pdf", 1); // 1 MB
//            var file2 = GetMockFile("doc2.pdf", 1); // 1 MB

//            var request = new UploadFileRequest
//            {
//                Files = new List<IFormFile> { file1, file2 },
//                FolderId = Guid.NewGuid() // Optional if your controller expects a folder
//            };

//            _fileManagerServiceMock
//                .Setup(x => x.GetAllFoldersWithFilesAsync(userId))
//                .ReturnsAsync(new List<FolderResponse> { new FolderResponse(Guid.NewGuid(), "Root", new List<FileResponse>(), new List<FolderResponse>(), null) });

//            _fileManagerServiceMock
//                .Setup(x => x.UploadFilesAsync(request, userId))
//                .ReturnsAsync((
//                    new List<FileResponse> {
//                new FileResponse(Guid.NewGuid(), "doc1.pdf", "https://storage.blob/core/doc1.pdf",null)
//                    },
//                    new List<string> { "doc2.pdf" }
//                ));

//            // Act
//            var result = await _controller.UploadFiles(request);

//            // Assert
//            var actionResult = Assert.IsType<OkObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("File upload completed", (string)response.meta.message);
//            Assert.Single(response.data.uploadedFiles);
//            Assert.Single(response.data.failedFiles);
//        }

//        [Fact]
//        public async Task UploadFiles_OversizedFiles_ReturnsBadRequest()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var oversizedFile = GetMockFile("bigfile.zip", 105); // 105MB
//            var request = new UploadFileRequest
//            {
//                Files = new List<IFormFile> { oversizedFile }
//            };

//            var result = await _controller.UploadFiles(request);

//            var actionResult = Assert.IsType<BadRequestObjectResult>(result);
//            var response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(actionResult.Value));

//            Assert.Equal("No files were uploaded. Some files exceed the 100MB size limit.", (string)response.meta.message);
//            Assert.Equal(0, (int)response.meta.code);

//            Assert.NotNull(response.data.oversizedFiles);
//            Assert.Single(response.data.oversizedFiles);
//        }

//        #endregion

//        #region Get Folder

//        [Fact]
//        public async Task GetAllFoldersWithFiles_ValidUser_ReturnsOk()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);
//            var folders = new List<FolderResponse>
//        {
//            new FolderResponse(Guid.NewGuid(), "Folder1", new List<FileResponse>(), new List<FolderResponse>(),null)
//        };
//            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(folders);
//            var result = await _controller.GetFolders(null) as OkObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//        }

//        [Fact]
//        public async Task GetFolderById_FolderExists_ReturnsOk()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);
//            // Arrange
//            var folderId = Guid.NewGuid();
//            var folderResponse = new FolderResponse(
//                folderId,
//                "Folder1",
//                new List<FileResponse>(),
//                new List<FolderResponse>(),
//                null
//            );

//            _fileManagerServiceMock
//                .Setup(x => x.GetFolderByIdAsync(folderId))
//                .ReturnsAsync(folderResponse); // Correct method setup

//            // Act
//            var result = await _controller.GetFolders(folderId) as OkObjectResult;

//            // Assert
//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//            var jsonString = JsonConvert.SerializeObject(result.Value);
//            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);
//            Assert.NotNull(response);
//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("Folder retrieved successfully", (string)response.meta.message);
//        }

//        [Fact]
//        public async Task GetFolderById_FolderNotFound_ReturnsNotFound()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var folderId = Guid.NewGuid();

//            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync((FolderResponse)null);

//            var result = await _controller.GetFolders(folderId) as NotFoundObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(404, result.StatusCode);
//            var jsonString = JsonConvert.SerializeObject(result.Value);
//            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);
//            Assert.Equal(0, (int)response.meta.code);
//            Assert.Equal("Folder not found", (string)response.meta.message);
//        }

//        [Fact]
//        public async Task GetAllFolders_NoFoldersExist_CreatesRootFolder()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var rootFolder = new FolderResponse(Guid.NewGuid(), "Root", new List<FileResponse>(), new List<FolderResponse>(), null);

//            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(new List<FolderResponse>());
//            _fileManagerServiceMock.Setup(x => x.CreateRootFolderAsync()).ReturnsAsync(rootFolder);

//            var result = await _controller.GetFolders(null) as OkObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//            var jsonString = JsonConvert.SerializeObject(result.Value);
//            dynamic response = JsonConvert.DeserializeObject<dynamic>(jsonString);
//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("Root folder retrieved successfully", (string)response.meta.message);
//            Assert.Equal("Root", (string)response.data.Name.ToString());
//        }

//        [Fact]
//        public async Task GetFolderById_ValidRequest_LogsAction()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var folderId = Guid.NewGuid();
//            var folderResponse = new FolderResponse(folderId, "TestFolder", new List<FileResponse>(), new List<FolderResponse>(), null);

//            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync(folderResponse);

//            var result = await _controller.GetFolders(folderId) as OkObjectResult;

//            Assert.NotNull(result);
           
//        }

//        [Fact]
//        public async Task GetFolderById_ResponseDataIsCorrect()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var folderId = Guid.NewGuid();
//            var fileId = Guid.NewGuid();

//            var folderResponse = new FolderResponse(
//                folderId,
//                "MyFolder",
//                new List<FileResponse> { new FileResponse(fileId, "myfile.txt", "url", null) },
//                new List<FolderResponse>(),
//                null
//            );

//            _fileManagerServiceMock.Setup(x => x.GetFolderByIdAsync(folderId)).ReturnsAsync(folderResponse);

//            var result = await _controller.GetFolders(folderId) as OkObjectResult;

//            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
//            Assert.Equal("MyFolder", (string)response.data.Name.ToString());
//            Assert.Single(response.data.Files);
//            Assert.Equal("myfile.txt", (string)response.data.Files[0].Name.ToString());
//        }


//        [Fact]
//        public async Task GetAllFoldersWithSubfoldersAndFiles_ReturnsNestedStructure()
//        {
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            var subFolder = new FolderResponse(Guid.NewGuid(), "Sub", new List<FileResponse>(), new List<FolderResponse>(), null);
//            var rootFolder = new FolderResponse(Guid.NewGuid(), "Root", new List<FileResponse>(), new List<FolderResponse> { subFolder }, null);

//            _fileManagerServiceMock.Setup(x => x.GetAllFoldersWithFilesAsync(userId)).ReturnsAsync(new List<FolderResponse> { rootFolder });

//            var result = await _controller.GetFolders(null) as OkObjectResult;

//            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
//            Assert.Equal("Root", (string)response.data.Name.ToString());
//            Assert.Single(response.data.SubFolders);
//            Assert.Equal("Sub", (string)response.data.SubFolders[0].Name.ToString());
//        }

//        #endregion

//        #region File
//        [Fact]
//        public async Task GetFileById_FileExists_ReturnsOk()
//        {
//            var fileId = Guid.NewGuid();
//            var file = new FileResponse(fileId, "file.txt", "blob-url", null);

//            _fileManagerServiceMock.Setup(x => x.GetFileByIdAsync(fileId)).ReturnsAsync(file);

//            var context = new DefaultHttpContext();

//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = context
//            };

//            var result = await _controller.GetFileById(fileId) as OkObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//            dynamic response = JsonConvert.DeserializeObject<dynamic>(JsonConvert.SerializeObject(result.Value));
//            Assert.Equal(1, (int)response.meta.code);
//            Assert.Equal("File retrieved successfully", (string)response.meta.message);
//           //_loggingServiceMock.Verify(x => x.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Once);
//        }

//        //[Fact]
//        //public async Task GetFileById_FileNotFound_ReturnsNotFound()
//        //{
//        //    var fileId = Guid.NewGuid();
//        //    _fileManagerServiceMock.Setup(x => x.GetFileByIdAsync(fileId)).ReturnsAsync((FileResponse)null);

//        //    var context = new DefaultHttpContext();

//        //    _controller.ControllerContext = new ControllerContext
//        //    {
//        //        HttpContext = context
//        //    };

//        //    var result = await _controller.GetFileById(fileId) as NotFoundObjectResult;

//        //    Assert.NotNull(result);
//        //    Assert.Equal(404, result.StatusCode);
//        //    //_loggingServiceMock.Verify(x => x.LogAsync("GetFileById", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Once);
//        //}

//        #endregion

//        #region DownloadFile

//        [Fact]
//        public async Task DownloadFile_FileExists_ReturnsFile()
//        {
//            var fileId = Guid.NewGuid();
//            var fileName = "test.txt";
//            var fileStream = new MemoryStream(Encoding.UTF8.GetBytes("Test file content"));
//            var contentType = "text/plain";

//            _fileManagerServiceMock.Setup(x => x.DownloadFileAsync(fileId))
//                .ReturnsAsync((fileStream, fileName, contentType));

//            var context = new DefaultHttpContext();

//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = context
//            };

//            var result = await _controller.DownloadFile(fileId) as FileStreamResult;

//            Assert.NotNull(result);
//            Assert.Equal(contentType, result.ContentType);
//            Assert.Equal(fileName, result.FileDownloadName);
//           // _loggingServiceMock.Verify(x => x.LogAsync("DownloadFile", TrackedEntity.File, fileId, null,
//              //  It.Is<object>(o => o.ToString().Contains(fileName)), null, "", ""), Times.Once);
//        }

//        [Fact]
//        public async Task DownloadFile_FileNotFound_ReturnsNotFound()
//        {
//            var fileId = Guid.NewGuid();
//            _fileManagerServiceMock.Setup(x => x.DownloadFileAsync(fileId))
//                .ReturnsAsync((null as Stream, null, null));

//            var result = await _controller.DownloadFile(fileId) as NotFoundObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(404, result.StatusCode);
//        }
//        #endregion

//        #region DeleteFile

//        [Fact]
//        public async Task DeleteFile_FileExists_ReturnsOk()
//        {
//            var fileId = Guid.NewGuid();
//            _fileManagerServiceMock.Setup(x => x.DeleteFileAsync(fileId)).ReturnsAsync(true);
//            var context = new DefaultHttpContext();

//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = context
//            };
//            var result = await _controller.DeleteFile(fileId) as OkObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//          //  _loggingServiceMock.Verify(x => x.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Once);
//        }

//        [Fact]
//        public async Task DeleteFile_FileNotFound_ReturnsNotFound()
//        {
//            var fileId = Guid.NewGuid();
//            _fileManagerServiceMock.Setup(x => x.DeleteFileAsync(fileId)).ReturnsAsync(false);

//            var result = await _controller.DeleteFile(fileId) as NotFoundObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(404, result.StatusCode);
//            _loggingServiceMock.Verify(x => x.LogAsync("DeleteFile", TrackedEntity.File, fileId, null, null, null, "", ""), Times.Never);
//        }
//        #endregion

//        #region DeleteFolder

//        [Fact]
//        public async Task DeleteFolder_FolderExists_ReturnsOk()
//        {
//            var folderId = Guid.NewGuid();
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            _fileManagerServiceMock.Setup(x => x.DeleteFolderAsync(folderId)).ReturnsAsync(true);

//            var result = await _controller.DeleteFolder(folderId) as OkObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(200, result.StatusCode);
//           // _loggingServiceMock.Verify(x => x.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString(), "", ""), Times.Once);
//        }

//        [Fact]
//        public async Task DeleteFolder_FolderNotFound_ReturnsBadRequest()
//        {
//            var folderId = Guid.NewGuid();
//            var userId = Guid.NewGuid();
//            SetUser(userId);

//            _fileManagerServiceMock.Setup(x => x.DeleteFolderAsync(folderId)).ReturnsAsync(false);

//            var result = await _controller.DeleteFolder(folderId) as BadRequestObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(400, result.StatusCode);
//           // _loggingServiceMock.Verify(x => x.LogAsync("DeleteFolder", TrackedEntity.Folder, folderId, null, null, userId.ToString(), "", ""), Times.Once);
//        }

//        [Fact]
//        public async Task DeleteFolder_Unauthorized_ReturnsUnauthorized()
//        {
//            // Don't call SetUser to simulate unauthorized access
//            var folderId = Guid.NewGuid();

//            var context = new DefaultHttpContext();

//            _controller.ControllerContext = new ControllerContext
//            {
//                HttpContext = context
//            };

//            var result = await _controller.DeleteFolder(folderId) as UnauthorizedObjectResult;

//            Assert.NotNull(result);
//            Assert.Equal(401, result.StatusCode);
//            _loggingServiceMock.Verify(x => x.LogErrorAsync("Unauthorized file upload attempt", "Invalid token", "Anonymous"), Times.Once);
//        }
//        #endregion
//    }
//}
