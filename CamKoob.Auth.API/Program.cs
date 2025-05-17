using System.Security.Cryptography;
using System.Text;
using CamKoob.Auth.API.Models;
using CamKoob.Auth.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<RsaSecurityKey>(provider =>
{
    var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText("Keys/private.key"));
    return new RsaSecurityKey(rsa);
});


builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/api/v1/login/asymmetric", (
    [FromServices] ITokenService tokenService,
    [FromBody] LoginRequest request) =>
{
    if (request.Username == "admin" && request.Password == "123")
    {
        var token = tokenService.GenerateAsymToken("admin", "Administrator");
        return Results.Ok(new { token });
    }

    return Results.Unauthorized();
})
.WithOpenApi();

await app.RunAsync();