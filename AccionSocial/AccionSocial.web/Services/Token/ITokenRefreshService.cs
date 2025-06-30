namespace AccionSocial.web.Services.Token
{
    public interface ITokenRefreshService
    {
        Task<string?> RefreshTokenAsync();
        Task<bool> TryRefreshTokenAsync();

    }
}
