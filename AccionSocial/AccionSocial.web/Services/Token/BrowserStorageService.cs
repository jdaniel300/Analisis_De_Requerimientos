using Microsoft.JSInterop;

namespace AccionSocial.web.Services.Token
{
    public class BrowserTokenStorage : ITokenStorageService
    {
        private readonly IJSRuntime _jsRuntime;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<BrowserTokenStorage> _logger;
        private string _memoryToken; // Fallback en memoria

        public BrowserTokenStorage(
            IJSRuntime jsRuntime,
            IHttpContextAccessor httpContextAccessor,
            ILogger<BrowserTokenStorage> logger)
        {
            _jsRuntime = jsRuntime;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        public async Task SetTokenAsync(string token)
        {
            try
            {
                _memoryToken = token; // Siempre guardar en memoria

                // 1. Almacenar en cookies (para SSR)
                var response = _httpContextAccessor.HttpContext?.Response;
                if (response != null)
                {
                    response.Cookies.Append("authToken", token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = _httpContextAccessor.HttpContext.Request.IsHttps,
                        SameSite = SameSiteMode.Lax,
                        Expires = DateTimeOffset.Now.AddDays(1),
                        Domain = _httpContextAccessor.HttpContext.Request.Host.Host
                    });
                    _logger.LogInformation("Token almacenado en cookies");
                }

                // 2. Almacenar en localStorage (para WASM)
                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", token);
                    _logger.LogInformation("Token almacenado en localStorage");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al almacenar token. Usando fallback en memoria.");
                // El token ya está guardado en _memoryToken
            }
        }

        public async Task<string> GetTokenAsync()
        {
            const string cookieName = "authToken";
            try
            {
                // 1. Verificar HttpContext
                if (_httpContextAccessor.HttpContext == null)
                {
                    _logger.LogWarning("HttpContext es nulo al recuperar token");
                    return _memoryToken;
                }

                // 2. Verificar cookies (SSR)
                var cookieToken = _httpContextAccessor.HttpContext.Request.Cookies[cookieName];
                if (!string.IsNullOrEmpty(cookieToken))
                {
                    _logger.LogDebug("Token recuperado de cookies. Longitud: {Length}", cookieToken.Length);
                    _memoryToken = cookieToken; // Actualizar memoria como caché
                    return cookieToken;
                }

                _logger.LogWarning("Cookie no encontrada. Revisando otros almacenamientos...");

                // 3. Verificar memoria
                if (!string.IsNullOrEmpty(_memoryToken))
                {
                    _logger.LogDebug("Token recuperado de memoria");
                    return _memoryToken;
                }

                // 4. Verificar localStorage (WASM)
                if (IsClientSide())
                {
                    try
                    {
                        var jsToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", cookieName);
                        if (!string.IsNullOrEmpty(jsToken))
                        {
                            _logger.LogDebug("Token recuperado de localStorage");
                            _memoryToken = jsToken;
                            return jsToken;
                        }
                    }
                    catch (Exception jsEx)
                    {
                        _logger.LogError(jsEx, "Error al acceder a localStorage");
                    }
                }

                _logger.LogError("Token no encontrado en ningún almacenamiento disponible");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error crítico al recuperar token. Cookie presente: {_httpContextAccessor.HttpContext?.Request.Cookies.ContainsKey(cookieName)}");
                return _memoryToken;
            }
        }

        private bool IsClientSide()
        {
            
            return OperatingSystem.IsBrowser();
        }

        private bool IsStaticRendering()
        {
            // If HttpContext is null, we're likely in static rendering
            return _httpContextAccessor.HttpContext == null;
        }

        private void SetServerSideToken(string token)
        {
            var response = _httpContextAccessor.HttpContext?.Response;
            if (response != null)
            {
                response.Cookies.Append("authToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax, // Changed from None for better security
                    Expires = DateTimeOffset.Now.AddDays(7),
                    Domain = _httpContextAccessor.HttpContext.Request.Host.Host
                });
            }
        }

        private string GetServerSideToken()
        {
            return _httpContextAccessor.HttpContext?.Request.Cookies["authToken"];
        }

        public async Task RemoveTokenAsync()
        {
            try
            {
                // Remove server-side token first (always works)
                RemoveServerSideToken();

                // Only attempt localStorage removal if running on the client (not during static rendering)
                if (IsClientSide() && !IsStaticRendering())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "JS Interop not available during token removal");
                // Fallback to server-side removal only
                RemoveServerSideToken();
            }
        }

        private void RemoveServerSideToken()
        {
            var response = _httpContextAccessor.HttpContext?.Response;
            if (response != null)
            {
                response.Cookies.Delete("authToken");
            }
        }

        public async Task<bool> HasTokenAsync()
        {
            var token = await GetTokenAsync();
            return !string.IsNullOrEmpty(token);
        }
    }
}
