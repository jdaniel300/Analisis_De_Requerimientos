using AccionSocialModels;
using System.Security.Claims;

namespace AccionSocial.web.Services.Auth
{
    public interface ITokenService
    {
        string GenerateToken(Usuario user, IEnumerable<string> roles);
        ClaimsPrincipal ValidateToken(string token);
    }
}
