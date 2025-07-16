using AccionSocialModels.DTO;

namespace AccionSocial.web.Services.Tall
{
    public interface ITallerService
    {
        Task<ApiResponse> CrearTallerAsync(TallerDTO tallerDto);
        Task<ApiResponse> ListarTalleresAsync();
        Task<ApiResponse> EditarTallerAsync(int id, TallerDTO tallerDto);
        Task<ApiResponse> DeshabilitarTallerAsync(int id);
        Task<ApiResponse> EliminarTallerFisicoAsync(int id);
    }
}
