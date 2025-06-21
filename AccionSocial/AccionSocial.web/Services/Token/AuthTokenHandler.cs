using AccionSocial.web.Services.Token;
using System.Net;
using System.Net.Http.Headers;

namespace AccionSocial.web.Services.Token
{
    public class AuthTokenHandler : DelegatingHandler
    {
        private readonly ITokenStorageService _tokenStorage;
        private readonly ILogger<AuthTokenHandler> _logger;

        public AuthTokenHandler(
            ITokenStorageService tokenStorage,
            ILogger<AuthTokenHandler> logger)
        {
            _tokenStorage = tokenStorage;
            _logger = logger;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Skip auth for login endpoint
            if (request.RequestUri?.AbsolutePath.EndsWith("/api/auth/login", StringComparison.OrdinalIgnoreCase) == true)
            {
                return await base.SendAsync(request, cancellationToken);
            }

            try
            {
                var token = await _tokenStorage.GetTokenAsync();
                _logger.LogDebug($"Token retrieved for request: {request.RequestUri}");

                if (!string.IsNullOrEmpty(token))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _logger.LogDebug($"Bearer token attached to {request.Method} {request.RequestUri}");
                }
                else
                {
                    _logger.LogWarning($"No token available for {request.Method} {request.RequestUri}");
                    // Consider throwing a specific exception here if token is required
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to attach token to {request.Method} {request.RequestUri}");
                throw; // Re-throw to fail fast
            }

            var response = await base.SendAsync(request, cancellationToken);

            // Optional: Handle token refresh if response is 401
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Received 401 Unauthorized, possible token expiration");
                // Here you could implement token refresh logic if needed
            }

            return response;
        }
    }
}
