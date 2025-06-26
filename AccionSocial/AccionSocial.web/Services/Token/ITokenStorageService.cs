namespace AccionSocial.web.Services.Token
{
    public interface ITokenStorageService
    {
        Task<string> GetTokenAsync();
        Task SetTokenAsync(string token);
        Task RemoveTokenAsync();
        Task<bool> HasTokenAsync();

        Task<string> GetRefreshTokenAsync();
        Task SetRefreshTokenAsync(string refreshToken);
        Task RemoveRefreshTokenAsync();

    }

}
