using System.Text;
using System.Text.Json;

namespace AccionSocial.web.Services.Token
{
    public class TokenRefreshService : ITokenRefreshService
    {
        private readonly HttpClient _httpClient;
        private readonly ITokenStorageService _tokenStorage;
        private readonly ILogger<TokenRefreshService> _logger;
        private readonly string _refreshEndpoint = "/api/auth/refresh";

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
                // 1. Verificar si tenemos un refresh token disponible
                var refreshToken = await _tokenStorage.GetRefreshTokenAsync();
                if (string.IsNullOrEmpty(refreshToken))
                {
                    _logger.LogWarning("No refresh token available");
                    return null;
                }

                // 2. Crear la solicitud de refresh
                var request = new HttpRequestMessage(HttpMethod.Post, _refreshEndpoint);
                request.Content = new StringContent(
                    JsonSerializer.Serialize(new { refreshToken }),
                    Encoding.UTF8,
                    "application/json");

                // 3. Enviar la solicitud
                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"Refresh failed with status: {response.StatusCode}");
                    return null;
                }

                // 4. Leer la respuesta
                var responseContent = await response.Content.ReadAsStringAsync();
                var authResult = JsonSerializer.Deserialize<AuthResult>(responseContent);

                if (string.IsNullOrEmpty(authResult?.Token))
                {
                    _logger.LogError("Invalid refresh response - missing token");
                    return null;
                }

                // 5. Almacenar el nuevo token
                await _tokenStorage.SetTokenAsync(authResult.Token);
                if (!string.IsNullOrEmpty(authResult.RefreshToken))
                {
                    await _tokenStorage.SetRefreshTokenAsync(authResult.RefreshToken);
                }

                _logger.LogInformation("Token refreshed successfully");
                return authResult.Token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return null;
            }
        }

        public async Task<bool> TryRefreshTokenAsync()
        {
            return await RefreshTokenAsync() != null;
        }

        private class AuthResult
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}
 
