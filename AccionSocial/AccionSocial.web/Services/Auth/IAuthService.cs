using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Polly.Caching;

namespace AccionSocial.web.Services.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> AuthenticateAsync(LoginDTO loginDto);
        Task LogoutAsync();
        
        Task<RegisterResponse> RegisterAsync(RegistroDTO registerDto);
        Task<ResultadoDTO> RegisterByAdminAsync(RegistroDTO registerDto);

        
    }
}
