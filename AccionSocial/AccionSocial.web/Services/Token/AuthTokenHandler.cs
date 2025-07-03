using AccionSocial.web.Services.Token;
using System.Net;
using System.Net.Http.Headers;

namespace AccionSocial.web.Services.Token
{
    public class AuthTokenHandler : DelegatingHandler
    {
        private readonly ITokenStorageService _tokenStorage;
        private readonly ITokenRefreshService _tokenRefresh;
        private readonly ILogger<AuthTokenHandler> _logger;

        public AuthTokenHandler(
            ITokenStorageService tokenStorage,
            ITokenRefreshService tokenRefresh,
            ILogger<AuthTokenHandler> logger)
        {
            _tokenStorage = tokenStorage;
            _tokenRefresh = tokenRefresh;
            _logger = logger;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
    HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // 1. Saltar autenticación para endpoints de login/refresh
            if (IsAuthEndpoint(request.RequestUri))
            {
                return await base.SendAsync(request, cancellationToken);
            }

            // 2. Adjuntar token actual
            await AttachTokenAsync(request);

            // 3. Configuración de reintentos
            int maxRetryAttempts = 3;
            int currentAttempt = 0;
            HttpResponseMessage response = null;

            while (currentAttempt < maxRetryAttempts)
            {
                response = await base.SendAsync(request, cancellationToken);

                // 4. Si la respuesta es exitosa (200-299), retornar inmediatamente
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }

                // 5. Manejar 401 (token expirado o inválido)
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    currentAttempt++;
                    _logger.LogWarning($"Intento {currentAttempt} de {maxRetryAttempts} fallido (401 Unauthorized)");

                    // 6. Intentar refrescar el token (solo en el primer 401)
                    if (currentAttempt == 1)
                    {
                        var newToken = await _tokenRefresh.RefreshTokenAsync();
                        if (!string.IsNullOrEmpty(newToken))
                        {
                            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
                            continue; // Reintentar con el nuevo token
                        }
                    }

                    // 7. Esperar antes de reintentar (solo si no es el último intento)
                    if (currentAttempt < maxRetryAttempts)
                    {
                        await Task.Delay(1000, cancellationToken); // Esperar 1 segundo
                    }
                }
                else
                {
                    // 8. Si no es 401, retornar la respuesta directamente (ej. 403, 404, 500)
                    return response;
                }
            }

            // 9. Si se agotan los intentos, limpiar tokens y devolver el último 401
            _logger.LogError("Se agotaron los intentos de autenticación");
            await _tokenRefresh.ClearTokens();
            return response;
        }

        private bool IsAuthEndpoint(Uri requestUri)
        {
            if (requestUri == null) return false;
        
        var authEndpoints = new[] { "/api/auth/login", "/api/auth/refresh" };
        return authEndpoints.Any(endpoint => 
            requestUri.AbsolutePath.Contains(endpoint, StringComparison.OrdinalIgnoreCase));
        }

        private async Task AttachTokenAsync(HttpRequestMessage request)
        {
            try
            {
                var token = await _tokenStorage.GetTokenAsync();
                if (!string.IsNullOrEmpty(token))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al adjuntar token");
            }
        }

        private async Task<HttpResponseMessage> HandleUnauthorizedAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken,
            HttpResponseMessage originalResponse)
        {
            var newToken = await _tokenRefresh.RefreshTokenAsync();
            if (string.IsNullOrEmpty(newToken))
            {
                return originalResponse;
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
