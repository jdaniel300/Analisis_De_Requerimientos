using AccionSocial.web.Services.Usuario;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace AccionSocial.web.Controllers
{
    [Authorize]
    public class UsrActualController : Controller
    {
        private readonly IUsuarioService _usuarioService;
        private readonly ILogger<UsrActualController> _logger;
        private readonly IWebHostEnvironment _env;

        public UsrActualController(IUsuarioService usuarioService, ILogger<UsrActualController> logger)
        {
            _usuarioService = usuarioService;
            _logger = logger;
        }


        [HttpGet]
        public async Task<IActionResult> GetUserProfile()
        {
            try
            {
                var user = await _usuarioService.GetCurrentUserAsync();
                return Ok(user ?? CreateDefaultUserResponse());
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Autenticación fallida al obtener perfil");
                return Unauthorized(new { message = "Sesión expirada" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener usuario actual");
                return StatusCode(500, new { message = "Error al cargar datos del usuario" });
            }
        }

        private CurrentUserResponse CreateDefaultUserResponse()
        {
            return new CurrentUserResponse(
                UserId: 0,
                UserName: "Invitado",
                Email: string.Empty,
                Telefono: string.Empty,
                NombreCompleto: "Usuario no autenticado",
                Roles: new List<string> { "Invitado" },
                FechaCreacion: DateTime.MinValue,
                UltimoAcceso: DateTime.MinValue,
                Estado: false
            );
        }

        [HttpDelete("mi-usuario-actual")]
        public async Task<IActionResult> DeleteCurrentUser([FromBody] DeleteUserRequest request)
        {
            try
            {
                if (request == null || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new { message = "La contraseña es requerida" });
                }

                var result = await _usuarioService.DeleteCurrentUserAsync(request.Password);

                if (result.IsUnauthorized)
                {
                    return Unauthorized(new { message = result.ErrorMessage });
                }

                if (!result.Succeeded)
                {
                    return BadRequest(new { message = result.ErrorMessage ?? "No se pudo eliminar el usuario" });
                }

                // Limpiar sesión antes de retornar
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                return Ok(new
                {
                    success = true,
                    redirectUrl = "/Login/login?accountDeleted=true"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar usuario actual");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { message = "Error interno al eliminar el usuario" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> ObtenerImagenPerfil()
        {
            try
            {
                var imageStream = await _usuarioService.ObtenerImagenPerfil();
                return File(imageStream, "image/jpeg"); // Asume JPEG por defecto
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener imagen de perfil");
                var defaultImagePath = Path.Combine(_env.WebRootPath, "img", "default-avatar.jpg");
                return PhysicalFile(defaultImagePath, "image/jpeg");
            }
        }

        [HttpPost]
        public async Task<IActionResult> SubirImagenPerfil([FromForm] IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                    return BadRequest("No se proporcionó archivo");

                using var memoryStream = new MemoryStream();
                await file.CopyToAsync(memoryStream);
                memoryStream.Position = 0;

                var fileContent = new MultipartFormDataContent
                {
                    { new StreamContent(memoryStream), "file", file.FileName }
                };

                var imagePath = await _usuarioService.SubirImagenPerfil(fileContent);
                return Ok(new { imagePath });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al subir imagen de perfil");
                return StatusCode(500, new { error = ex.Message });
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

        [HttpPut("actualizarPerfil")]
        public async Task<IActionResult> ActualizarPerfil([FromBody] UsuarioUpdateDto updateDto)
        {
            try
            {
                var currentUser = await _usuarioService.GetCurrentUserAsync();
                if (currentUser == null)
                {
                    return Unauthorized(new { message = "Usuario no autenticado" });
                }

                var result = await _usuarioService.UpdateUserAsync(currentUser.UserId, updateDto);

                if (result)
                {
                    return Ok(new { message = "Perfil actualizado correctamente" });
                }

                return BadRequest(new { message = "Error al actualizar el perfil" });
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Autenticación fallida al actualizar perfil");
                return Unauthorized(new { message = ex.Message });
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogWarning(ex, "Usuario no encontrado al actualizar perfil");
                return NotFound(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogWarning(ex, "Datos inválidos al actualizar perfil");
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al actualizar perfil");
                return StatusCode(500, new { message = "Error interno al actualizar el perfil" });
            }
        }

        

       
    }
}
