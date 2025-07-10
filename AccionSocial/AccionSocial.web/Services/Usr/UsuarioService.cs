using AccionSocial.web.Services.Token;
using AccionSocial.web.Services.Usuario;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using System.Net;
using System.Net.Http.Headers;


namespace AccionSocial.web.Services.Usr
{
    public class UsuarioService : IUsuarioService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<UsuarioService> _logger;
        private readonly ITokenStorageService _tokenService;

        public UsuarioService(
            HttpClient httpClient,
            ILogger<UsuarioService> logger,
            ITokenStorageService tokenService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _tokenService = tokenService;
        }

        public async Task<CurrentUserResponse?> GetCurrentUserAsync()
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                throw new UnauthorizedAccessException("No hay token de autenticación disponible");
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "/api/usr/usuarioActual");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    await _tokenService.RemoveTokenAsync();
                    throw new UnauthorizedAccessException("Sesión expirada o token inválido");
                }

                response.EnsureSuccessStatusCode();

                return await response.Content.ReadFromJsonAsync<CurrentUserResponse>();
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "Error HTTP al obtener usuario actual");
                throw new Exception("Error al comunicarse con el servicio de usuarios", httpEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al obtener usuario actual");
                throw;
            }
        }

        public async Task<bool> DeleteCurrentUserAsync()
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                throw new UnauthorizedAccessException("No hay token de autenticación disponible");
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Delete, "/api/usr/usuarioActual");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    await _tokenService.RemoveTokenAsync();
                    throw new UnauthorizedAccessException("Sesión expirada o token inválido");
                }

                if (response.StatusCode == HttpStatusCode.NoContent)
                {
                    // Eliminar token local después de eliminar la cuenta
                    await _tokenService.RemoveTokenAsync();
                    return true;
                }

                // Si llegamos aquí, hubo un error
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new Exception($"Error al eliminar usuario: {errorContent}");
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "Error HTTP al eliminar usuario actual");
                throw new Exception("Error al comunicarse con el servicio de usuarios", httpEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al eliminar usuario actual");
                throw;
            }
        }

        public async Task<bool> DeleteUserByIdAsync(int id)
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                throw new UnauthorizedAccessException("No hay token de autenticación disponible");
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Delete, $"/api/usr/eliminar/{id}");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);

                // Manejo de respuestas
                switch (response.StatusCode)
                {
                    case HttpStatusCode.NoContent:
                        return true;

                    case HttpStatusCode.Unauthorized:
                        await _tokenService.RemoveTokenAsync();
                        throw new UnauthorizedAccessException("Sesión expirada o token inválido");

                    case HttpStatusCode.Forbidden:
                        throw new UnauthorizedAccessException("No tienes permisos de administrador");

                    case HttpStatusCode.NotFound:
                        throw new KeyNotFoundException("Usuario no encontrado");

                    case HttpStatusCode.BadRequest:
                        var errorContent = await response.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(errorContent);

                    default:
                        response.EnsureSuccessStatusCode();
                        return true;
                }
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "Error HTTP al eliminar usuario con ID {UserId}", id);
                throw new Exception("Error al comunicarse con el servicio de usuarios", httpEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al eliminar usuario con ID {UserId}", id);
                throw;
            }
        }

        public async Task<bool> UpdateUserAsync(int id, UsuarioUpdateDto updateDto)
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                throw new UnauthorizedAccessException("No hay token de autenticación disponible");
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Put, $"/api/usr/actualizarUsuario/{id}")
                {
                    Content = JsonContent.Create(updateDto)
                };

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        return true;

                    case HttpStatusCode.Unauthorized:
                        await _tokenService.RemoveTokenAsync();
                        throw new UnauthorizedAccessException("Sesión expirada o token inválido");

                    case HttpStatusCode.Forbidden:
                        throw new UnauthorizedAccessException("No tienes permisos para esta acción");

                    case HttpStatusCode.NotFound:
                        throw new KeyNotFoundException("Usuario no encontrado");

                    case HttpStatusCode.BadRequest:
                        var errorContent = await response.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(errorContent);

                    default:
                        response.EnsureSuccessStatusCode();
                        return true;
                }
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "Error HTTP al actualizar usuario con ID {UserId}", id);
                throw new Exception("Error al comunicarse con el servicio de usuarios", httpEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al actualizar usuario con ID {UserId}", id);
                throw;
            }
        }


    }
}
