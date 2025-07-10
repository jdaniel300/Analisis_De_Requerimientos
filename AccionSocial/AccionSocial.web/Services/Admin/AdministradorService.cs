using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.WebUtilities;
using NuGet.Protocol;
using Polly.Caching;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace AccionSocial.web.Services.Admin
{
    public class AdministradorService : IAdministradorService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<AdministradorService> _logger;
       

        // Usamos este constructor (inyectamos HttpClient directamente)
        public AdministradorService(
            IHttpClientFactory httpClientFactory,
            ILogger<AdministradorService> logger
            )
        {
            _httpClient = httpClientFactory.CreateClient("AccionSocialApi");
            _logger = logger;
            
        }

        public async Task<PaginacionResponse<ListaUsuariosDTO>> ObtenerUsuariosPaginados(
        int pagina = 1, int tamanoPagina = 10, string filtro = "", string sortOrder = "")
        {
            _logger.LogInformation("Iniciando ObtenerUsuariosPaginados - Página: {Pagina}, Tamaño: {TamanoPagina}", pagina, tamanoPagina);

            try
            {
                // Validación de parámetros
                pagina = Math.Max(1, pagina);
                tamanoPagina = Math.Clamp(tamanoPagina, 1, 100);

                // Configuración de serialización
                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new DateOnlyJsonConverter() }
                };

                // Construcción de la URL
                var queryParams = new Dictionary<string, string>
                {
                    ["pagina"] = pagina.ToString(),
                    ["tamanoPagina"] = tamanoPagina.ToString(),
                    ["filtro"] = WebUtility.UrlEncode(filtro ?? string.Empty),
                    ["sortOrder"] = WebUtility.UrlEncode(sortOrder ?? string.Empty)
                };

                var requestUri = QueryHelpers.AddQueryString("api/consultas/admin/usuarios", queryParams);
                _logger.LogDebug("Solicitando datos a: {RequestUri}", requestUri);

                // Ejecución de la solicitud (el token se maneja automáticamente por AuthTokenHandler)
                var response = await _httpClient.GetAsync(requestUri);

                // Procesamiento de la respuesta
                response.EnsureSuccessStatusCode(); // Lanza excepción si hay error

                var content = await response.Content.ReadAsStringAsync();
                _logger.LogDebug("Respuesta recibida: {Content}", content);

                var result = JsonSerializer.Deserialize<PaginacionResponse<ListaUsuariosDTO>>(content, jsonOptions);

                _logger.LogInformation("Obtenidos {Count} usuarios de {Total}",
                    result?.Datos?.Count ?? 0,
                    result?.Total ?? 0);

                return result ?? new PaginacionResponse<ListaUsuariosDTO>
                {
                    Pagina = pagina,
                    TamanoPagina = tamanoPagina,
                    Total = 0,
                    Datos = new List<ListaUsuariosDTO>()
                };
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Acceso no autorizado - Redirigiendo a login");
                throw new UnauthorizedAccessException("Acceso denegado. Por favor inicie sesión nuevamente.", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error crítico en ObtenerUsuariosPaginados");
                throw new ApplicationException("Error al obtener la lista de usuarios. Por favor intente nuevamente.", ex);
            }
        }

        public async Task<ResultadoDTO> RegistrarUsuarioAsync(RegistroDTO registerDto)
        {
            _logger.LogInformation("Iniciando registro de nuevo usuario como administrador");

            try
            {
                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new DateOnlyJsonConverter() }
                };

                var response = await _httpClient.PostAsJsonAsync("/api/auth/admin/register", registerDto);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error en el registro. Código: {StatusCode}, Respuesta: {Response}",
                        response.StatusCode, responseContent);

                    try
                    {
                        var errorResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent, jsonOptions);
                        return new ResultadoDTO
                        {
                            Success = false,
                            Message = errorResponse?.ContainsKey("Message") == true ?
                                      errorResponse["Message"].ToString() : "Error en el registro",
                            Errors = errorResponse?.ContainsKey("Errors") == true ?
                                     ((JsonElement)errorResponse["Errors"]).EnumerateArray().Select(x => x.ToString()).ToList() :
                                     new List<string> { responseContent }
                        };
                    }
                    catch
                    {
                        return new ResultadoDTO
                        {
                            Success = false,
                            Message = "Error en el registro",
                            Errors = new List<string> { responseContent }
                        };
                    }
                }

                _logger.LogInformation("Usuario registrado exitosamente");

                try
                {
                    var successResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent, jsonOptions);
                    return new ResultadoDTO
                    {
                        Success = true,
                        Message = successResponse?.ContainsKey("Message") == true ?
                                  successResponse["Message"].ToString() : "Usuario registrado exitosamente"
                    };
                }
                catch
                {
                    return new ResultadoDTO
                    {
                        Success = true,
                        Message = "Usuario registrado exitosamente"
                    };
                }
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Acceso no autorizado durante el registro de usuario");
                throw new UnauthorizedAccessException("Acceso denegado. Por favor inicie sesión nuevamente.", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al registrar usuario como administrador");
                return new ResultadoDTO
                {
                    Success = false,
                    Message = "Error al registrar usuario",
                    Errors = new List<string> { ex.Message }
                };
            }
        }

        public async Task<IEnumerable<Rol>> ObtenerRolesAsync()
        {
            try
            {
                // Hacer la solicitud GET al endpoint
                var response = await _httpClient.GetAsync("api/consultas/roles/");

                // Verificar si la respuesta fue exitosa
                response.EnsureSuccessStatusCode();

                // Leer y deserializar la respuesta
                var roles = await response.Content.ReadFromJsonAsync<IEnumerable<Rol>>();

                return roles ?? Enumerable.Empty<Rol>();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Error al obtener los roles");
                throw; // Puedes manejar esto de otra forma si lo prefieres
            }
        }

        
    }

}

