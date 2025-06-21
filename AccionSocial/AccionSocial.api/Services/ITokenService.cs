using AccionSocialModels;
using System.Security.Claims;

namespace AccionSocial.web.Services.Token
{
    public interface ITokenService
    {
        string GenerateJwtToken(Usuario user, IList<string> roles);
        bool ValidateToken(string token);
        ClaimsPrincipal GetPrincipalFromToken(string token);
    }
}
