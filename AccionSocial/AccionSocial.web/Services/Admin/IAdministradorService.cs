using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Polly.Caching;

namespace AccionSocial.web.Services.Admin
{
    public interface IAdministradorService
    {
        Task<IEnumerable<Rol>> ObtenerRolesAsync();
        Task<PaginacionResponse<ListaUsuariosDTO>> ObtenerUsuariosPaginados(
        int pagina = 1,
        int tamanoPagina = 10,
        string filtro = "",
        string sortOrder = "");
        Task<ResultadoDTO> RegistrarUsuarioAsync(RegistroDTO registerDto);
        
    }
}
