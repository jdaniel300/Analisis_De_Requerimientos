using AccionSocialModels.DTO;
using AccionSocialModels.Response;

namespace AccionSocial.web.Views.ViewModel
{
    public class AdminUsuariosViewModel
    {
        public PaginacionResponse<ListaUsuariosDTO> Usuarios { get; set; }
        public RegistroDTO RegistroModel { get; set; }
    }
}
