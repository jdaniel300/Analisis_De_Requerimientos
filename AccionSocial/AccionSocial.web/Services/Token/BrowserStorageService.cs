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
                _memoryToken = token;

                // Almacenar en cookies (SSR)
                var response = _httpContextAccessor.HttpContext?.Response;
                if (response != null)
                {
                    response.Cookies.Append("authToken", token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = _httpContextAccessor.HttpContext.Request.IsHttps,
                        SameSite = SameSiteMode.Lax,
                        Expires = DateTimeOffset.Now.AddDays(1)
                    });
                }

                // Almacenar en localStorage (WASM)
                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", token);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al almacenar token");
            }
        }

        public async Task<string> GetTokenAsync()
        {
            try
            {
                if (!string.IsNullOrEmpty(_memoryToken))
                    return _memoryToken;

                if (_httpContextAccessor.HttpContext?.Request.Cookies.TryGetValue("authToken", out var cookieToken) == true)
                {
                    _memoryToken = cookieToken;
                    return cookieToken;
                }

                if (IsClientSide())
                {
                    var jsToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "authToken");
                    if (!string.IsNullOrEmpty(jsToken))
                    {
                        _memoryToken = jsToken;
                        return jsToken;
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener token");
                return null;
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

        public async Task SetRefreshTokenAsync(string refreshToken)
        {
            try
            {
                _httpContextAccessor.HttpContext?.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.Now.AddDays(30)
                });

                if (IsClientSide())
                {
                    await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", refreshToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al almacenar refresh token");
            }
        }

        public async Task<string> GetRefreshTokenAsync()
        {
            try
            {
                if (_httpContextAccessor.HttpContext?.Request.Cookies.TryGetValue("refreshToken", out var cookieToken) == true)
                {
                    return cookieToken;
                }

                if (IsClientSide())
                {
                    return await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener refresh token");
                return null;
            }
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
