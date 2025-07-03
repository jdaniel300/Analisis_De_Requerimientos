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
            // Bloqueo para evitar múltiples refrescos simultáneos
            if (!await _refreshLock.WaitAsync(TimeSpan.Zero))
            {
                _logger.LogWarning("Operación de refresco ya en curso");
                return null;
            }

            try
            {
                // 1. Verificar si ya hay un token válido (evitar refresco innecesario)
                var currentToken = await _tokenStorage.GetTokenAsync();
                if (!string.IsNullOrEmpty(currentToken) && !IsTokenExpired(currentToken))
                {
                    return currentToken;
                }

                // 2. Obtener refresh token
                var refreshToken = await _tokenStorage.GetRefreshTokenAsync();
                if (string.IsNullOrEmpty(refreshToken))
                {
                    _logger.LogWarning("No hay refresh token disponible");
                    await ClearTokens();
                    return null;
                }

                // 3. Preparar petición de refresco
                var request = new HttpRequestMessage(HttpMethod.Post, RefreshEndpoint)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new { RefreshToken = refreshToken }),
                        Encoding.UTF8,
                        "application/json")
                };

                // 4. Enviar petición SIN token de acceso (para evitar bucles)
                _logger.LogInformation("Refrescando token...");
                var response = await _httpClient.SendAsync(request);

                // 5. Manejar respuesta
                switch (response.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        _logger.LogWarning("Refresh token rechazado - Requiere nuevo login");
                        await ClearTokens();
                        return null;

                    case HttpStatusCode.TooManyRequests:
                        _logger.LogWarning("Demasiados intentos de refresco");
                        await Task.Delay(5000); // Esperar antes de reintentar
                        return null;

                    default:
                        response.EnsureSuccessStatusCode();
                        break;
                }

                // 6. Procesar nueva autenticación
                var authResult = await ProcessAuthResponse(response);
                if (authResult == null) return null;

                // 7. Actualizar almacenamiento
                await _tokenStorage.SetTokenAsync(authResult.Token);
                if (!string.IsNullOrEmpty(authResult.RefreshToken))
                {
                    await _tokenStorage.SetRefreshTokenAsync(authResult.RefreshToken);
                }

                return authResult.Token;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        private async Task<AuthResult?> ProcessAuthResponse(HttpResponseMessage response)
        {
            try
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<AuthResult>(responseContent);

                if (string.IsNullOrEmpty(result?.Token))
                {
                    _logger.LogWarning("Token no recibido en respuesta");
                    await ClearTokens();
                    return null;
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando respuesta de autenticación");
                await ClearTokens();
                return null;
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

        public async Task ClearTokens()
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
 
