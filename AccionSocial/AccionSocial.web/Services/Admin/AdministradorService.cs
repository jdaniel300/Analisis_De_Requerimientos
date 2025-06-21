using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
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
            int pagina = 1, int tamanoPagina = 10, string filtro = "", string sortOrder = "")
        {
            _logger.LogInformation("Iniciando ObtenerUsuariosPaginados");
            try
            {
                // Parameter validation
                if (pagina < 1) pagina = 1;
                if (tamanoPagina < 1 || tamanoPagina > 100) tamanoPagina = 10;

                // Get and validate token
                var token = await _tokenService.GetTokenAsync();
                if (string.IsNullOrEmpty(token))
                {
                    throw new UnauthorizedAccessException("No authentication token available");
                }

                // Configure HttpClient
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // Build query string
                var queryParams = new Dictionary<string, string>
                {
                    ["pagina"] = pagina.ToString(),
                    ["tamanoPagina"] = tamanoPagina.ToString(),
                    ["filtro"] = WebUtility.UrlEncode(filtro ?? ""),
                    ["sortOrder"] = WebUtility.UrlEncode(sortOrder ?? "")
                };

                var requestUri = QueryHelpers.AddQueryString("api/consultas/admin/usuarios", queryParams);
                _logger.LogDebug($"Request URI: {requestUri}");

                var response = await _httpClient.GetAsync(requestUri);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"API Error: {errorContent}");

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new UnauthorizedAccessException("Access denied. Please login again.");
                    }

                    response.EnsureSuccessStatusCode();
                }

                var content = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<PaginacionResponse<ListaUsuariosDTO>>(content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ObtenerUsuariosPaginados");
                throw;
            }
        }


    }


}
