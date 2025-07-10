using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AccionSocial.web.Services.Usuario
{
    public interface IUsuarioService
    {
        Task<CurrentUserResponse?> GetCurrentUserAsync();
        Task<bool> DeleteCurrentUserAsync();

        Task<bool> DeleteUserByIdAsync(int id);

        Task<bool> UpdateUserAsync(int id, UsuarioUpdateDto updateDto);
    }
}
