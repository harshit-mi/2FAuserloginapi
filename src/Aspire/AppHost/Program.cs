var builder = DistributedApplication.CreateBuilder(args);

var api = builder.AddProject<Projects.Api>("api");

var redis = builder.AddRedis("cache");

api.WithReference(redis);

builder.Build().Run();