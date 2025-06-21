using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Extensions.Caching.Memory;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly ITokenStorageService _tokenService;
    private readonly ILogger<AuthService> _logger;
    private readonly IMemoryCache _cache;

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
    }

    public async Task<LoginResponse> AuthenticateAsync(LoginDTO loginDto)
    {
        try
        {
            _logger.LogInformation("Iniciando autenticación para {Username}", loginDto.UsernameOrEmail);

            // 1. Realizar la solicitud de login
            var response = await _httpClient.PostAsJsonAsync("/api/auth/login", loginDto);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogDebug("Respuesta de la API: {StatusCode} - {Content}",
                response.StatusCode, responseContent);

            // 2. Validar respuesta
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Autenticación fallida. Status: {StatusCode}", response.StatusCode);
                throw new UnauthorizedAccessException(
                    response.StatusCode == HttpStatusCode.Unauthorized
                        ? "Credenciales inválidas"
                        : $"Error en el servidor: {response.StatusCode}");
            }

            // 3. Deserializar respuesta
            var result = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? throw new InvalidOperationException("Respuesta inválida del servidor");

            // 4. Validar token recibido
            if (string.IsNullOrWhiteSpace(result.Token))
            {
                _logger.LogError("Token recibido es nulo o vacío");
                throw new InvalidOperationException("Token inválido recibido del servidor");
            }

            _logger.LogInformation("Autenticación exitosa para {Username}", result.User?.userName);

            // 5. Almacenamiento del token con verificación
            try
            {
                await _tokenService.SetTokenAsync(result.Token);

                // Verificación en 2 pasos
                var storedToken = await _tokenService.GetTokenAsync();
                if (storedToken != result.Token)
                {
                    _logger.LogWarning("El token no se almacenó correctamente. Se usará en memoria para esta sesión.");
                    // Mantenemos el token en el objeto de respuesta como fallback
                }
                else
                {
                    _logger.LogDebug("Token almacenado correctamente");
                }
            }
            catch (Exception storageEx)
            {
                _logger.LogError(storageEx, "Error al almacenar el token. Se usará en memoria.");
                // Continuamos devolviendo el response aunque falle el almacenamiento
            }

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

    public class ServiceUnavailableException : Exception
    {
        public ServiceUnavailableException(string message, Exception inner)
            : base(message, inner) { }
    }

    public async Task LogoutAsync()
    {
        try
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token)) return;

            // 1. Invalidate server-side token
            try
            {
                var response = await _httpClient.PostAsync("/api/auth/logout", null);
                if (!response.IsSuccessStatusCode)
                    _logger.LogWarning("Failed to invalidate server token. Status: {StatusCode}", response.StatusCode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating server token");
            }

            // 2. Clear local token (handles SSR safely)
            await _tokenService.RemoveTokenAsync();
            _cache.Set($"invalid_token_{token}", true, TimeSpan.FromMinutes(15));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in LogoutAsync");
            throw; // Re-throw to let the caller handle it
        }
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        var token = await _tokenService.GetTokenAsync();
        if (string.IsNullOrEmpty(token)) return false;
        if (_cache.TryGetValue($"invalid_token_{token}", out _)) return false;

        try
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetAsync("/api/auth/validate-token");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return true; // Fail open
        }
    }

    public async Task<LoginResponse> GetCurrentUserAsync()
    {
        var token = await _tokenService.GetTokenAsync();
        if (string.IsNullOrEmpty(token))
            throw new UnauthorizedAccessException("No hay token de autenticación");

        try
        {
            // No necesitamos crear client ni añadir headers manualmente
            var response = await _httpClient.GetAsync("/api/auth/current-user");

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

    public async Task<string> GetTokenAsync() => await _tokenService.GetTokenAsync();

    public async Task<RegisterResponse> RegisterAsync(RegistroDTO registerDto)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("/api/auth/register", registerDto);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Error en registro: {Error}", errorContent);

                // Manejo mejorado de errores estructurados
                throw await ParseErrorResponse(response);
            }

            var registerResponse = await response.Content.ReadFromJsonAsync<RegisterResponse>();

            // Auto-login si viene token en la respuesta
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

    // Método auxiliar para parsear errores
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


