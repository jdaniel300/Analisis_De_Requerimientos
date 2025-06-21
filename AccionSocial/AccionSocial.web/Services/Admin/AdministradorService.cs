using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.WebUtilities;
using NuGet.Protocol;
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
        private readonly ITokenStorageService _tokenService;

        // Usamos este constructor (inyectamos HttpClient directamente)
        public AdministradorService(
            HttpClient httpClient,
            ILogger<AdministradorService> logger,
            ITokenStorageService tokenService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _tokenService = tokenService;
        }

        public async Task<PaginacionResponse<ListaUsuariosDTO>> ObtenerUsuariosPaginados(
     int pagina = 1,
     int tamanoPagina = 10,
     string filtro = "",
     string sortOrder = "")
        {
            _logger.LogInformation("Iniciando ObtenerUsuariosPaginados - Página: {Pagina}, Tamaño: {TamanoPagina}", pagina, tamanoPagina);

            try
            {
                // 1. Validación de parámetros
                pagina = Math.Max(1, pagina);
                tamanoPagina = Math.Clamp(tamanoPagina, 1, 100);

                // 2. Obtención y validación del token
                var token = await _tokenService.GetTokenAsync();
                if (string.IsNullOrEmpty(token))
                {
                    _logger.LogWarning("No se encontró token de autenticación");
                    throw new UnauthorizedAccessException("No authentication token available");
                }

                // 3. Configuración del HttpClient
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                _httpClient.DefaultRequestHeaders.Accept.Clear();
                _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // 4. Configuración de serialización JSON
                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new DateOnlyJsonConverter() }
                };

                // 5. Construcción de la URL
                var queryParams = new Dictionary<string, string>
                {
                    ["pagina"] = pagina.ToString(),
                    ["tamanoPagina"] = tamanoPagina.ToString(),
                    ["filtro"] = WebUtility.UrlEncode(filtro ?? string.Empty),
                    ["sortOrder"] = WebUtility.UrlEncode(sortOrder ?? string.Empty)
                };

                var requestUri = QueryHelpers.AddQueryString("api/consultas/admin/usuarios", queryParams);
                _logger.LogDebug("Solicitando datos a: {RequestUri}", requestUri);

                // 6. Ejecución de la solicitud HTTP
                var response = await _httpClient.GetAsync(requestUri);

                // 7. Manejo de errores HTTP
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error en la API - Código: {StatusCode}, Respuesta: {ErrorContent}",
                        response.StatusCode, errorContent);

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new UnauthorizedAccessException("Access denied. Please login again.");
                    }

                    response.EnsureSuccessStatusCode(); // Lanza excepción para otros códigos de error
                }

                // 8. Procesamiento de la respuesta
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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error crítico en ObtenerUsuariosPaginados");
                throw new ApplicationException("Error al obtener la lista de usuarios. Por favor intente nuevamente.", ex);
            }
        }


    }
}
