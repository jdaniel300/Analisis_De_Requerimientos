using AccionSocial.web.Services.Usuario;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AccionSocial.web.Controllers
{
    [Authorize]
    public class UsrActualController : Controller
    {
        private readonly IUsuarioService _usuarioService;

        public UsrActualController(IUsuarioService usuarioService)
        {
            _usuarioService = usuarioService;
        }

        [HttpGet("mi-usuario-actual")]
        public async Task<IActionResult> GetCurrentUser()
        {
            try
            {
                var user = await _usuarioService.GetCurrentUserAsync();

                if (user == null)
                    return NotFound("Usuario no encontrado");

                return Ok(user);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error interno al obtener el usuario actual");
            }
        }

        [HttpDelete("mi-usuario-actual")]
        public async Task<IActionResult> DeleteCurrentUser()
        {
            try
            {
                var result = await _usuarioService.DeleteCurrentUserAsync();

                if (result)
                {
                    return NoContent(); // 204 No Content
                }

                return BadRequest("No se pudo eliminar el usuario");
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error interno al eliminar el usuario");
            }
        }

        [Authorize(Roles = "Admin")] // Requiere rol de Admin
        [HttpDelete("eliminar/{id}")]
        public async Task<IActionResult> DeleteUserById(int id)
        {
            try
            {
                var result = await _usuarioService.DeleteUserByIdAsync(id);

                if (result)
                {
                    return NoContent(); // 204 No Content
                }

                return BadRequest("No se pudo eliminar el usuario");
            }
            catch (UnauthorizedAccessException ex)
            {
                return ex.Message.Contains("administrador")
                    ? Forbid() // 403 Forbid para falta de permisos
                    : Unauthorized(ex.Message); // 401 para otros casos
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error interno al eliminar el usuario");
            }
        }

        [Authorize]
        [HttpPut("actualizar-usuario/{id}")]
        public async Task<IActionResult> UpdateUser(int id, [FromBody] UsuarioUpdateDto updateDto)
        {
            try
            {
                var result = await _usuarioService.UpdateUserAsync(id, updateDto);

                if (result)
                {
                    return Ok(); // 200 OK
                }

                return BadRequest("No se pudo actualizar el usuario");
            }
            catch (UnauthorizedAccessException ex)
            {
                return ex.Message.Contains("permisos")
                    ? Forbid() // 403 Forbid para falta de permisos
                    : Unauthorized(ex.Message); // 401 para otros casos
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error interno al actualizar el usuario");
            }
        }
    }
}
