namespace CamKoob.Auth.API.Services;

public interface ITokenService
{
    string GenerateToken(string username, string role);
    string GenerateAsymToken(string username, string role);
}