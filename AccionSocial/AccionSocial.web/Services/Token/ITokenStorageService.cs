namespace AccionSocial.web.Services.Token
{
    public interface ITokenStorageService
    {
        Task SetTokenAsync(string token);
        Task<string> GetTokenAsync();
        Task RemoveTokenAsync();

        Task<bool> HasTokenAsync();

        Task SetRefreshTokenAsync(string refreshToken);
        Task<string> GetRefreshTokenAsync();
        Task RemoveRefreshTokenAsync();
    }
}
