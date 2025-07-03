using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;

namespace AccionSocial.web.Services.Token
{
    public class BrowserTokenStorage : ITokenStorageService
    {
        private readonly IJSRuntime _jsRuntime;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<BrowserTokenStorage> _logger;
        private string _memoryToken;
        private string _memoryRefreshToken;

        public BrowserTokenStorage(
            IJSRuntime jsRuntime,
            IHttpContextAccessor httpContextAccessor,
            ILogger<BrowserTokenStorage> logger)
        {
            _jsRuntime = jsRuntime;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        public async Task<string> GetTokenAsync()
        {
            try
            {
                // 1. Check memory cache first
                if (!string.IsNullOrEmpty(_memoryToken))
                    return _memoryToken;

                // 2. Check SSR cookies (server-side)
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    var cookieToken = httpContext.Request.Cookies["authToken"];
                    if (!string.IsNullOrEmpty(cookieToken))
                    {
                        _memoryToken = cookieToken;
                        return cookieToken;
                    }
                }

                // 3. Check WASM localStorage (client-side)
                if (IsClientSide())
                {
                    try
                    {
                        var jsToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "authToken");
                        if (!string.IsNullOrEmpty(jsToken))
                        {
                            _memoryToken = jsToken;
                            // Sync to cookies if we're in SSR mode
                            if (httpContext != null)
                            {
                                SetTokenInCookies(jsToken);
                            }
                            return jsToken;
                        }
                    }
                    catch (JSException ex)
                    {
                        _logger.LogWarning(ex, "Error accessing localStorage for authToken");
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting auth token");
                return null;
            }
        }
        private void SetTokenInCookies(string token)
        {
            var response = _httpContextAccessor.HttpContext?.Response;
            if (response != null && !response.HasStarted)
            {
                _logger.LogDebug("Setting authToken cookie. Response has started: {HasStarted}", response.HasStarted);

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTimeOffset.Now.AddDays(1),
                    Path = "/"
                };

                response.Cookies.Append("authToken", token, cookieOptions);
                _logger.LogInformation("AuthToken cookie set successfully");
            }
            else
            {
                _logger.LogWarning("Cannot set authToken cookie - Response is null or has started");
            }
        }

        public async Task<string> GetRefreshTokenAsync()
        {
            try
            {
                // 1. Check memory cache first
                if (!string.IsNullOrEmpty(_memoryRefreshToken))
                    return _memoryRefreshToken;

                // 2. Check SSR cookies (server-side)
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    var cookieRefreshToken = httpContext.Request.Cookies["refreshToken"];
                    if (!string.IsNullOrEmpty(cookieRefreshToken))
                    {
                        _memoryRefreshToken = cookieRefreshToken;
                        return cookieRefreshToken;
                    }
                }

                // 3. Check WASM localStorage (client-side)
                if (IsClientSide())
                {
                    try
                    {
                        var jsRefreshToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
                        if (!string.IsNullOrEmpty(jsRefreshToken))
                        {
                            _memoryRefreshToken = jsRefreshToken;
                            // Sync to cookies if we're in SSR mode
                            if (httpContext != null)
                            {
                                SetRefreshTokenInCookies(jsRefreshToken);
                            }
                            return jsRefreshToken;
                        }
                    }
                    catch (JSException ex)
                    {
                        _logger.LogWarning(ex, "Error accessing localStorage for refreshToken");
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting refresh token");
                return null;
            }
        }

        public async Task SetRefreshTokenAsync(string refreshToken)
        {
            try
            {
                _memoryRefreshToken = refreshToken;

                // Set in SSR cookies
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    SetRefreshTokenInCookies(refreshToken);
                }

                // Set in WASM localStorage
                if (IsClientSide())
                {
                    try
                    {
                        await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", refreshToken);
                    }
                    catch (JSException ex)
                    {
                        _logger.LogWarning(ex, "Error setting refreshToken in localStorage");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting refresh token");
            }
        }


        private void SetRefreshTokenInCookies(string refreshToken)
        {
            var response = _httpContextAccessor.HttpContext?.Response;
            if (response != null && !response.HasStarted)
            {
                response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTimeOffset.Now.AddDays(30),
                    Path = "/"  // Asegurarse de que la cookie esté disponible en todas las rutas
                });
            }
        }

        public async Task SetTokenAsync(string token)
        {
            try
            {
                _memoryToken = token;

                // Set in SSR cookies
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    SetTokenInCookies(token);
                }

                // Set in WASM localStorage
                if (IsClientSide())
                {
                    try
                    {
                        await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", token);
                    }
                    catch (JSException ex)
                    {
                        _logger.LogWarning(ex, "Error setting authToken in localStorage");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting auth token");
            }
        }

        

        public async Task RemoveTokenAsync()
        {
            try
            {
                _memoryToken = null;
                _httpContextAccessor.HttpContext?.Response.Cookies.Delete("authToken");

                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar token");
            }
        }

        public async Task<bool> HasTokenAsync()
        {
            return !string.IsNullOrEmpty(await GetTokenAsync());
        }

        public async Task ClearTokenAsync() {
            RemoveTokenAsync();
            RemoveRefreshTokenAsync();

            
        }

        public async Task RemoveRefreshTokenAsync()
        {
            try
            {
                _httpContextAccessor.HttpContext?.Response.Cookies.Delete("refreshToken");

                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "refreshToken");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar refresh token");
            }
        }

        private bool IsClientSide() => OperatingSystem.IsBrowser();
    }
}
