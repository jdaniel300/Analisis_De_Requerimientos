using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.Extensions.Caching.Memory;
using Polly.Caching;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly ITokenStorageService _tokenService;
    private readonly ILogger<AuthService> _logger;
    private readonly IMemoryCache _cache;
    private bool _isRefreshing = false;
    private Queue<TaskCompletionSource<string>> _refreshQueue = new Queue<TaskCompletionSource<string>>();

    public AuthService(
        HttpClient httpClient,
        ITokenStorageService tokenService,
        ILogger<AuthService> logger,
        IMemoryCache cache)
    {
        _httpClient = httpClient;
        _tokenService = tokenService;
        _logger = logger;
        _cache = cache;

        // Configurar interceptores
        ConfigureHttpClient();
    }

    private void ConfigureHttpClient()
    {
        _httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task<LoginResponse> AuthenticateAsync(LoginDTO loginDto)
    {
        try
        {
            _logger.LogInformation("Iniciando autenticación para {Username}", loginDto.UsernameOrEmail);

            var response = await _httpClient.PostAsJsonAsync("/api/auth/login", loginDto);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Autenticación fallida. Status: {StatusCode} - {Content}",
                    response.StatusCode, errorContent);
                throw new UnauthorizedAccessException("Credenciales inválidas");
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("Respuesta de login: {Content}", responseContent);

            // Deserializar la respuesta
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            // Validar y extraer token
            if (!responseObj.TryGetProperty("token", out var tokenProp) ||
                string.IsNullOrEmpty(tokenProp.GetString()))
            {
                throw new InvalidOperationException("Token inválido o faltante en la respuesta");
            }

            // Construir objeto de respuesta
            var result = new LoginResponse
            {
                Token = tokenProp.GetString()!,
                RefreshToken = responseObj.TryGetProperty("refreshToken", out var rt) ? rt.GetString() : null,
                User = new LoginResponse.UserData()
            };

            // Extraer datos de usuario si existen
            if (responseObj.TryGetProperty("user", out var userProp))
            {
                result.User.userName = userProp.TryGetProperty("userName", out var un) ? un.GetString() : null;
                result.User.email = userProp.TryGetProperty("email", out var em) ? em.GetString() : null;
                result.User.nombreCompleto = userProp.TryGetProperty("nombreCompleto", out var nc) ? nc.GetString() : null;

                if (userProp.TryGetProperty("roles", out var rolesProp))
                {
                    result.User.roles = JsonSerializer.Deserialize<List<string>>(rolesProp.ToString());
                }
            }

            // Almacenar tokens
            await _tokenService.SetTokenAsync(result.Token);
            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                await _tokenService.SetRefreshTokenAsync(result.RefreshToken);
            }

            _logger.LogInformation("Autenticación exitosa para {Username}", result.User?.userName);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error durante la autenticación");
            throw;
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token)) return;

            // 1. Invalidar token en el servidor
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Failed to invalidate server token. Status: {StatusCode}", response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating server token");
            }

            // 2. Limpiar tokens locales
            await _tokenService.RemoveTokenAsync();
            await _tokenService.RemoveRefreshTokenAsync();
            _cache.Remove($"invalid_token_{token}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in LogoutAsync");
            throw;
        }
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        var token = await _tokenService.GetTokenAsync();
        if (string.IsNullOrEmpty(token)) return false;
        if (_cache.TryGetValue($"invalid_token_{token}", out _)) return false;

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/validate-token");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<LoginResponse> GetCurrentUserAsync()
    {
        var token = await _tokenService.GetTokenAsync();
        if (string.IsNullOrEmpty(token))
            throw new UnauthorizedAccessException("No hay token de autenticación");

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/current-user");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                await _tokenService.RemoveTokenAsync();
                throw new UnauthorizedAccessException("Sesión expirada");
            }

            response.EnsureSuccessStatusCode();

            var user = await response.Content.ReadFromJsonAsync<LoginResponse>()
                ?? throw new Exception("Respuesta del servidor inválida");

            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al obtener usuario actual");
            throw new Exception("Error al comunicarse con el servicio de autenticación", ex);
        }
    }

    public async Task<RegisterResponse> RegisterAsync(RegistroDTO registerDto)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("/api/auth/register", registerDto);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Error en registro: {Error}", errorContent);
                throw await ParseErrorResponse(response);
            }

            var registerResponse = await response.Content.ReadFromJsonAsync<RegisterResponse>();

            if (!string.IsNullOrEmpty(registerResponse?.Token))
            {
                await _tokenService.SetTokenAsync(registerResponse.Token);
            }

            return registerResponse ?? throw new Exception("Respuesta de registro inválida");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error en RegisterAsync");
            throw;
        }
    }

    public async Task<string> RefreshTokenAsync()
    {
        var refreshToken = await _tokenService.GetRefreshTokenAsync();
        var currentToken = await _tokenService.GetTokenAsync();

        if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(currentToken))
        {
            throw new UnauthorizedAccessException("No hay tokens disponibles para refrescar");
        }

        if (_isRefreshing)
        {
            var tcs = new TaskCompletionSource<string>();
            _refreshQueue.Enqueue(tcs);
            return await tcs.Task;
        }

        _isRefreshing = true;

        try
        {
            _logger.LogInformation("Intentando refrescar token...");

            var response = await _httpClient.PostAsJsonAsync("/api/auth/refresh-token", new
            {
                Token = currentToken,
                RefreshToken = refreshToken
            });

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Error al refrescar token. Status: {StatusCode}", response.StatusCode);
                throw new UnauthorizedAccessException("Error al refrescar token de acceso");
            }

            var result = await response.Content.ReadFromJsonAsync<RefreshTokenResponse>();

            if (string.IsNullOrEmpty(result?.Token))
            {
                throw new InvalidOperationException("Token inválido recibido del servidor");
            }

            // Almacenar nuevos tokens
            await _tokenService.SetTokenAsync(result.Token);
            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                await _tokenService.SetRefreshTokenAsync(result.RefreshToken);
            }

            _logger.LogInformation("Token refrescado exitosamente");

            // Notificar a los esperando
            while (_refreshQueue.Count > 0)
            {
                _refreshQueue.Dequeue().SetResult(result.Token);
            }

            return result.Token;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al refrescar token");

            // Limpiar tokens en caso de error
            await _tokenService.RemoveTokenAsync();
            await _tokenService.RemoveRefreshTokenAsync();

            // Notificar error a los esperando
            while (_refreshQueue.Count > 0)
            {
                _refreshQueue.Dequeue().SetException(ex);
            }

            throw;
        }
        finally
        {
            _isRefreshing = false;
        }
    }

    public async Task<HttpResponseMessage> SendAuthorizedRequestAsync(HttpRequestMessage request)
    {
        var token = await _tokenService.GetTokenAsync();
        if (string.IsNullOrEmpty(token))
        {
            throw new UnauthorizedAccessException("No autenticado");
        }

        // Agregar token a la solicitud
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Enviar solicitud
        var response = await _httpClient.SendAsync(request);

        // Si el token expiró, intentar refrescar
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            try
            {
                var newToken = await RefreshTokenAsync();

                // Reintentar la solicitud con el nuevo token
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
                return await _httpClient.SendAsync(request);
            }
            catch
            {
                // Si no se pudo refrescar, limpiar tokens y lanzar excepción
                await _tokenService.RemoveTokenAsync();
                await _tokenService.RemoveRefreshTokenAsync();
                throw new UnauthorizedAccessException("Sesión expirada");
            }
        }

        return response;
    }

    private async Task<Exception> ParseErrorResponse(HttpResponseMessage response)
    {
        try
        {
            var errorResponse = await response.Content.ReadFromJsonAsync<ErrorResponse>();
            return new Exception(errorResponse?.Message ?? "Error en el registro");
        }
        catch
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            return new Exception(errorContent);
        }
    }
    public async Task<ResultadoDTO> RegisterByAdminAsync(RegistroDTO registerDto)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("api/auth/admin/register", registerDto);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ResultadoDTO>();
                return result ?? new ResultadoDTO { Success = true, Message = "Usuario registrado exitosamente" };
            }

            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogError("Error al registrar usuario por admin: {Error}", errorContent);

            return new ResultadoDTO
            {
                Success = false,
                Message = "Error al registrar usuario",
                Errors = new List<string> { errorContent }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al registrar usuario por admin");
            return new ResultadoDTO
            {
                Success = false,
                Message = "Error interno al registrar usuario",
                Errors = new List<string> { ex.Message }
            };
        }
    }
}


public class ServiceUnavailableException : Exception
{
    public ServiceUnavailableException(string message, Exception inner)
        : base(message, inner) { }
}



