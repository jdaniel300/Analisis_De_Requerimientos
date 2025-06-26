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
            // Skip auth for login and refresh endpoints
            if (IsAuthEndpoint(request.RequestUri))
            {
                return await base.SendAsync(request, cancellationToken);
            }

            await AttachTokenAsync(request);

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return await HandleUnauthorizedAsync(request, cancellationToken, response);
            }

            return response;
        }

        private bool IsAuthEndpoint(Uri requestUri)
        {
            return requestUri?.AbsolutePath.EndsWith("/api/auth/login", StringComparison.OrdinalIgnoreCase) == true ||
                   requestUri?.AbsolutePath.EndsWith("/api/auth/refresh-token", StringComparison.OrdinalIgnoreCase) == true;
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
