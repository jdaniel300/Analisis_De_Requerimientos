using AccionSocial.web.Services.Token;
using AccionSocial.web.Services.Usuario;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;


namespace AccionSocial.web.Services.Usr
{
    public class UsuarioService : IUsuarioService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<UsuarioService> _logger;
        private readonly ITokenStorageService _tokenService;
        private readonly IWebHostEnvironment _env;
        private readonly ITokenRefreshService _tokenRefreshService;

        public UsuarioService(
            HttpClient httpClient,
            ILogger<UsuarioService> logger,
            ITokenStorageService tokenService,
            IWebHostEnvironment env,
            ITokenRefreshService tokenRefreshService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _tokenService = tokenService;
            _env = env;
            _tokenRefreshService = tokenRefreshService;
        }

        public async Task<CurrentUserResponse?> GetCurrentUserAsync()
        {
            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Intento de obtener usuario actual sin token");
                throw new UnauthorizedAccessException("No hay token de autenticación disponible");
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "/api/usr/usuarioActual");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        // Intento refrescar el token
                        var newToken = await _tokenRefreshService.RefreshTokenAsync();
                        if (newToken == null)
                        {
                            await _tokenService.RemoveTokenAsync();
                            throw new UnauthorizedAccessException("Sesión expirada o token inválido");
                        }

                        // Reintentar la petición con el nuevo token
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
                        response = await _httpClient.SendAsync(request);
                        response.EnsureSuccessStatusCode();
                        break;

                    case HttpStatusCode.NotFound:
                        throw new KeyNotFoundException("Usuario no encontrado");

                    case HttpStatusCode.Forbidden:
                        throw new UnauthorizedAccessException("No tiene permisos para esta acción");
                }


                response.EnsureSuccessStatusCode();

                return await response.Content.ReadFromJsonAsync<CurrentUserResponse>();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Error HTTP al obtener usuario actual");
                throw new ApplicationException("Error al comunicarse con el servidor", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al obtener usuario actual");
                throw;
            }
        }

        public async Task<Stream> ObtenerImagenPerfil()
        {
            try
            {
                var token = await _tokenService.GetTokenAsync();
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.GetAsync("api/usr/obtenerImagenPerfil");

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStreamAsync();
                }

                // Si hay error, devolver imagen por defecto
                _logger.LogWarning("No se pudo obtener la imagen de perfil, usando imagen por defecto. Status: {StatusCode}", response.StatusCode);
                return GetDefaultImageStream();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener imagen de perfil");
                return GetDefaultImageStream();
            }
        }

        private Stream GetDefaultImageStream()
        {
            var defaultImagePath = Path.Combine(_env.WebRootPath, "img", "default-avatar.jpg");
            return new FileStream(defaultImagePath, FileMode.Open, FileAccess.Read);
        }

        public async Task<string> SubirImagenPerfil(MultipartFormDataContent fileContent)
        {
            try
            {
                var token = await _tokenService.GetTokenAsync();
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.PostAsync("api/usr/subirImagenPerfil", fileContent);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error al subir imagen: {StatusCode} - {Error}", response.StatusCode, errorContent);
                    throw new HttpRequestException($"Error al subir imagen: {errorContent}");
                }

                var result = await response.Content.ReadFromJsonAsync<ImageUploadResponse>();
                return result?.ImagePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al subir imagen de perfil");
                throw;
            }
        }

        public async Task<DeleteUserResult> DeleteCurrentUserAsync(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return DeleteUserResult.Failure("La contraseña es requerida");
            }

            var token = await _tokenService.GetTokenAsync();
            if (string.IsNullOrEmpty(token))
            {
                return DeleteUserResult.Unauthorized("No hay token de autenticación disponible");
            }

            try
            {
                var deleteRequest = new { Password = password };
                var jsonContent = JsonSerializer.Serialize(deleteRequest);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var request = new HttpRequestMessage(HttpMethod.Delete, "/api/usr/usuarioActual")
                {
                    Content = content,
                    Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) }
                };

                var response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    await _tokenService.RemoveTokenAsync();
                    return DeleteUserResult.Success();
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    await _tokenService.RemoveTokenAsync();
                    return DeleteUserResult.Unauthorized("Sesión expirada o token inválido");
                }

                var errorContent = await response.Content.ReadAsStringAsync();
                return DeleteUserResult.Failure(errorContent);
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "Error HTTP al eliminar usuario actual");
                return DeleteUserResult.Failure("Error al comunicarse con el servicio de usuarios");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al eliminar usuario actual");
                return DeleteUserResult.Failure("Error inesperado al eliminar el usuario");
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
