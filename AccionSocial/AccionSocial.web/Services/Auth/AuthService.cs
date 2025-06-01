using AccionSocial.web.Services.Auth;
using AccionSocialModels;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Json;
using System.Text.Json;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly ITokenService _tokenService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthService(
        HttpClient httpClient,
        ITokenService tokenService,
        IHttpContextAccessor httpContextAccessor)
    {
        _httpClient = httpClient;
        _tokenService = tokenService;
        _httpContextAccessor = httpContextAccessor;
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<LoginResponse> AuthenticateAsync(LoginDTO loginDto)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("/auth/login", loginDto); // Usa el DTO directamente

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new UnauthorizedAccessException(errorContent);
            }

            return await response.Content.ReadFromJsonAsync<LoginResponse>();
        }
        catch (HttpRequestException ex)
        {
            throw new Exception("Error al comunicarse con el servicio de autenticación", ex);
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            // Consumir el endpoint de logout del API
            var response = await _httpClient.PostAsync("/api/auth/logout", null);

            // Eliminar la cookie local si existe
            _httpContextAccessor.HttpContext?.Response.Cookies.Delete("auth_token");

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Error al cerrar sesión");
            }
        }
        catch (HttpRequestException ex)
        {
            throw new Exception("Error al comunicarse con el servicio de autenticación", ex);
        }
    }

    public async Task<LoginResponse> GetCurrentUserAsync()
    {
        try
        {
            // Verificar si tenemos un token almacenado localmente
            var token = _httpContextAccessor.HttpContext?.Request.Cookies["auth_token"];
            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }

            // Consumir el endpoint del usuario actual del API
            var response = await _httpClient.GetAsync("/api/auth/current-user");

            if (!response.IsSuccessStatusCode)
            {
                throw new UnauthorizedAccessException("Usuario no autenticado");
            }

            return await response.Content.ReadFromJsonAsync<LoginResponse>();
        }
        catch (HttpRequestException ex)
        {
            throw new Exception("Error al comunicarse con el servicio de autenticación", ex);
        }
    }
}

