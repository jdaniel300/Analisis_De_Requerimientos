using System.Text;
using System.Text.Json;

namespace AccionSocial.web.Services.Token
{
    public class TokenRefreshService : ITokenRefreshService
    {
        private readonly HttpClient _httpClient;
        private readonly ITokenStorageService _tokenStorage;
        private readonly ILogger<TokenRefreshService> _logger;
        private const string RefreshEndpoint = "/api/auth/refresh-token";

        public TokenRefreshService(
            HttpClient httpClient,
            ITokenStorageService tokenStorage,
            ILogger<TokenRefreshService> logger)
        {
            _httpClient = httpClient;
            _tokenStorage = tokenStorage;
            _logger = logger;
        }

        public async Task<string?> RefreshTokenAsync()
        {
            try
            {
                var refreshToken = await _tokenStorage.GetRefreshTokenAsync();
                var currentToken = await _tokenStorage.GetTokenAsync();

                if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(currentToken))
                {
                    _logger.LogWarning("No hay token o refresh token disponible");
                    return null;
                }

                var request = new HttpRequestMessage(HttpMethod.Post, RefreshEndpoint)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new
                        {
                            Token = currentToken,
                            RefreshToken = refreshToken
                        }),
                        Encoding.UTF8,
                        "application/json")
                };

                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    await ClearTokens();
                    return null;
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var authResult = JsonSerializer.Deserialize<AuthResult>(responseContent);

                if (string.IsNullOrEmpty(authResult?.Token))
                {
                    await ClearTokens();
                    return null;
                }

                await _tokenStorage.SetTokenAsync(authResult.Token);

                if (!string.IsNullOrEmpty(authResult.RefreshToken))
                {
                    await _tokenStorage.SetRefreshTokenAsync(authResult.RefreshToken);
                }

                return authResult.Token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al refrescar token");
                await ClearTokens();
                return null;
            }
        }

        public async Task<bool> TryRefreshTokenAsync()
        {
            return await RefreshTokenAsync() != null;
        }

        private async Task ClearTokens()
        {
            await _tokenStorage.RemoveTokenAsync();
            await _tokenStorage.RemoveRefreshTokenAsync();
        }

        private class AuthResult
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}
 
