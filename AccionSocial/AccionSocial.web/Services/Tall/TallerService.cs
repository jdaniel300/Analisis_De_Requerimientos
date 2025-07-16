using AccionSocialModels.DTO;
using System.Text.Json;

namespace AccionSocial.web.Services.Tall
{
    public class TallerService :ITallerService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<TallerService> _logger;

        public TallerService(
            IHttpClientFactory httpClientFactory,
            ILogger<TallerService> logger)
        {
            _httpClient = httpClientFactory.CreateClient("AccionSocialApi");
            _logger = logger;
        }

        public async Task<ApiResponse> CrearTallerAsync(TallerDTO tallerDto)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync("/api/taller/crear", tallerDto);
                return await HandleResponse(response, $"Taller '{tallerDto.Nombre}' creado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al crear taller");
                return new ApiResponse
                {
                    Success = false,
                    Message = $"Error interno al crear taller: {ex.Message}",
                    Data = null
                };
            }
        }

        public async Task<ApiResponse> ListarTalleresAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/taller/listar");
                return await HandleResponse(response, "Lista de talleres obtenida exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al listar talleres");
                return new ApiResponse
                {
                    Success = false,
                    Message = $"Error interno al listar talleres: {ex.Message}",
                    Data = null
                };
            }
        }

        public async Task<ApiResponse> EditarTallerAsync(int id, TallerDTO tallerDto)
        {
            try
            {
                var response = await _httpClient.PutAsJsonAsync($"/api/taller/editar/{id}", tallerDto);
                return await HandleResponse(response, $"Taller con ID {id} actualizado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al editar taller con ID: {Id}", id);
                return new ApiResponse
                {
                    Success = false,
                    Message = $"Error interno al editar taller: {ex.Message}",
                    Data = null
                };
            }
        }

        public async Task<ApiResponse> DeshabilitarTallerAsync(int id)
        {
            try
            {
                var response = await _httpClient.DeleteAsync($"/api/taller/desabilitar/{id}");
                return await HandleResponse(response, $"Taller con ID {id} deshabilitado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al deshabilitar taller con ID: {Id}", id);
                return new ApiResponse
                {
                    Success = false,
                    Message = $"Error interno al deshabilitar taller: {ex.Message}",
                    Data = null
                };
            }
        }

        public async Task<ApiResponse> EliminarTallerFisicoAsync(int id)
        {
            try
            {
                var response = await _httpClient.DeleteAsync($"/api/taller/eliminar-fisico/{id}");
                return await HandleResponse(response, $"Taller con ID {id} eliminado permanentemente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar taller físico con ID: {Id}", id);
                return new ApiResponse
                {
                    Success = false,
                    Message = $"Error interno al eliminar taller: {ex.Message}",
                    Data = null
                };
            }
        }

        private async Task<ApiResponse> HandleResponse(HttpResponseMessage response, string successMessage)
        {
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                try
                {
                    var result = JsonSerializer.Deserialize<ApiResponse>(content, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    // Si la API ya devuelve un ApiResponse estructurado, lo retornamos directamente
                    if (result != null)
                    {
                        return result;
                    }

                    // Si la respuesta no es un ApiResponse, creamos uno
                    return new ApiResponse
                    {
                        Success = true,
                        Message = successMessage,
                        Data = content
                    };
                }
                catch (JsonException)
                {
                    // Si no se puede deserializar como ApiResponse, asumimos que es el dato directo
                    return new ApiResponse
                    {
                        Success = true,
                        Message = successMessage,
                        Data = content
                    };
                }
            }

            _logger.LogError("Error en la respuesta. Código: {StatusCode}, Respuesta: {Content}",
                response.StatusCode, content);

            try
            {
                // Intentamos deserializar el error como ApiResponse
                var errorResponse = JsonSerializer.Deserialize<ApiResponse>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                return errorResponse ?? new ApiResponse
                {
                    Success = false,
                    Message = content,
                    Data = null
                };
            }
            catch (JsonException)
            {
                return new ApiResponse
                {
                    Success = false,
                    Message = content,
                    Data = null
                };
            }
        }
    }
}
