using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;

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
                // 1. Check memory first (fastest)
                if (!string.IsNullOrEmpty(_memoryToken))
                {
                    _logger.LogDebug("Token recuperado de memoria");
                    return _memoryToken;
                }

                // 2. Check HttpContext cookies if available
                if (_httpContextAccessor.HttpContext != null)
                {
                    // Only check Request.Cookies - Response.Cookies is for writing only
                    var cookieToken = _httpContextAccessor.HttpContext.Request.Cookies[cookieName];
                    if (!string.IsNullOrEmpty(cookieToken))
                    {
                        _memoryToken = cookieToken;
                        _logger.LogDebug("Token recuperado de cookies HTTP");
                        return cookieToken;
                    }
                }

                // 3. Check localStorage for WASM
                if (IsClientSide())
                {
                    try
                    {
                        var jsToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", cookieName);
                        if (!string.IsNullOrEmpty(jsToken))
                        {
                            _memoryToken = jsToken;
                            _logger.LogDebug("Token recuperado de localStorage");
                            return jsToken;
                        }
                    }
                    catch (Exception jsEx)
                    {
                        _logger.LogError(jsEx, "Error al acceder a localStorage");
                    }
                }
                _logger.LogWarning("No se pudo recuperar el token de ningún almacenamiento");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al recuperar token");
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

        public async Task SetRefreshTokenAsync(string refreshToken)
        {
            try
            {
                // Similar a SetTokenAsync pero para refresh token
                var response = _httpContextAccessor.HttpContext?.Response;
                if (response != null)
                {
                    response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict,
                        Expires = DateTimeOffset.Now.AddDays(30)
                    });
                }

                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", refreshToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing refresh token");
            }
        }

        public async Task<string> GetRefreshTokenAsync()
        {
            try
            {
                // 1. Check cookies first
                if (_httpContextAccessor.HttpContext != null)
                {
                    var cookieToken = _httpContextAccessor.HttpContext.Request.Cookies["refreshToken"];
                    if (!string.IsNullOrEmpty(cookieToken))
                    {
                        return cookieToken;
                    }
                }

                // 2. Check localStorage for WASM
                if (IsClientSide())
                {
                    return await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting refresh token");
                return null;
            }
        }

        public async Task RemoveRefreshTokenAsync()
        {
            try
            {
                // Remove from cookies
                _httpContextAccessor.HttpContext?.Response.Cookies.Delete("refreshToken");

                // Remove from localStorage
                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "refreshToken");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing refresh token");
            }
        }
    }
}
