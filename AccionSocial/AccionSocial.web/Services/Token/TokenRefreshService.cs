using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
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
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
        
        public TokenRefreshService(
            HttpClient httpClient,
            ITokenStorageService tokenStorage,
            ILogger<TokenRefreshService> logger)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _tokenStorage = tokenStorage ?? throw new ArgumentNullException(nameof(tokenStorage));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Verificar que la base address esté configurada
            if (_httpClient.BaseAddress == null)
            {
                throw new InvalidOperationException("HttpClient BaseAddress no está configurado");
            }
        }

        public async Task<string?> RefreshTokenAsync()
        {
            await _refreshLock.WaitAsync();
            try
            {
                // Verificar primero si ya tenemos un token válido
                var currentToken = await _tokenStorage.GetTokenAsync();
                if (!string.IsNullOrEmpty(currentToken) && !IsTokenExpired(currentToken))
                {
                    return currentToken;
                }

                var refreshToken = await _tokenStorage.GetRefreshTokenAsync();
                if (string.IsNullOrEmpty(refreshToken))
                {
                    _logger.LogWarning("No hay refresh token disponible");
                    await ClearTokens();
                    return null;
                }

                var request = new HttpRequestMessage(HttpMethod.Post, RefreshEndpoint)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new { RefreshToken = refreshToken }),
                        Encoding.UTF8,
                        "application/json")
                };

                // Agregar token actual si existe (para invalidación en el servidor)
                if (!string.IsNullOrEmpty(currentToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", currentToken);
                }

                _logger.LogInformation("Intentando refrescar token...");
                var response = await _httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    _logger.LogWarning("Refresh token rechazado - eliminando tokens");
                    await ClearTokens();
                    return null;
                }

                response.EnsureSuccessStatusCode();

                var responseContent = await response.Content.ReadAsStringAsync();
                var authResult = JsonSerializer.Deserialize<AuthResult>(responseContent);

                if (string.IsNullOrEmpty(authResult?.Token))
                {
                    _logger.LogWarning("Respuesta de refresco inválida");
                    await ClearTokens();
                    return null;
                }

                // Almacenar nuevos tokens
                await _tokenStorage.SetTokenAsync(authResult.Token);

                // Solo actualizar refresh token si viene uno nuevo
                if (!string.IsNullOrEmpty(authResult.RefreshToken))
                {
                    await _tokenStorage.SetRefreshTokenAsync(authResult.RefreshToken);
                }

                _logger.LogInformation("Token refrescado exitosamente");
                return authResult.Token;
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Refresh token inválido - eliminando tokens");
                await ClearTokens();
                return null;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Error de red al refrescar token");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al refrescar token");
                await ClearTokens();
                return null;
            }
            finally
            {
                _refreshLock.Release();
            }
        }
        

        public async Task<bool> TryRefreshTokenAsync()
        {
            try
            {
                var newToken = await RefreshTokenAsync();
                return newToken != null;
            }
            catch
            {
                return false;
            }
        }

        private async Task ClearTokens()
        {
            try
            {
                await _tokenStorage.RemoveTokenAsync();
                await _tokenStorage.RemoveRefreshTokenAsync();
                _logger.LogInformation("Tokens eliminados por seguridad");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al limpiar tokens");
            }
        }

        private bool IsTokenExpired(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);
                return jwtToken.ValidTo < DateTime.UtcNow.AddMinutes(1); 
            }
            catch
            {
                return true;
            }
        }

        private class AuthResult
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}
 
