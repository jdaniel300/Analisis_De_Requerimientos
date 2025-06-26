using AccionSocialModels;
using System.Security.Claims;

namespace AccionSocial.api.Services.Token
{
    public interface ITokenService
    {
        string GenerateJwtToken(Usuario user, IList<string> roles);
        bool ValidateToken(string token);
        ClaimsPrincipal GetPrincipalFromToken(string token);
        string GenerateRefreshToken();
        Task<bool> InvalidateTokenAsync(string token);
        Task<bool> IsTokenInvalidatedAsync(string token);

    }
}
