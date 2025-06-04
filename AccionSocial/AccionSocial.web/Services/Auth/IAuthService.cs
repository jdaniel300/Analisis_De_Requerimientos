using AccionSocialModels;

namespace AccionSocial.web.Services.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> AuthenticateAsync(LoginDTO loginDto);
        Task LogoutAsync();
        Task<LoginResponse> GetCurrentUserAsync();
        Task<RegisterResponse> RegisterAsync(RegistroDTO registerDto);
    }
}
