using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.Extensions.Caching.Memory;
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
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogDebug("Respuesta de la API: {StatusCode} - {Content}",
                response.StatusCode, responseContent);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Autenticación fallida. Status: {StatusCode}", response.StatusCode);
                throw new UnauthorizedAccessException(
                    response.StatusCode == HttpStatusCode.Unauthorized
                        ? "Credenciales inválidas"
                        : $"Error en el servidor: {response.StatusCode}");
            }

            var result = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? throw new InvalidOperationException("Respuesta inválida del servidor");

            if (string.IsNullOrWhiteSpace(result.Token))
            {
                _logger.LogError("Token recibido es nulo o vacío");
                throw new InvalidOperationException("Token inválido recibido del servidor");
            }

            // Almacenar token y refresh token
            await _tokenService.SetTokenAsync(result.Token);
            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                await _tokenService.SetRefreshTokenAsync(result.RefreshToken);
            }

            _logger.LogInformation("Autenticación exitosa para {Username}", result.User?.userName);
            return result;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Error al deserializar la respuesta del servidor");
            throw new InvalidOperationException("Formato de respuesta inválido", ex);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Error de conexión con el servidor");
            throw new ServiceUnavailableException("No se pudo conectar con el servidor", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error inesperado durante la autenticación");
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
}

public class ServiceUnavailableException : Exception
{
    public ServiceUnavailableException(string message, Exception inner)
        : base(message, inner) { }
}

public class RefreshTokenResponse
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}

public class ErrorResponse
{
    public string Message { get; set; }
}


