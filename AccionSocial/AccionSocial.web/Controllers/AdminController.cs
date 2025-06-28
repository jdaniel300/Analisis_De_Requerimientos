using AccionSocial.web.Models;
using AccionSocial.web.Services.Admin;
using AccionSocial.web.Services.Token;
using AccionSocial.web.Views.ViewModel;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Polly.Caching;
using System.Diagnostics;
using System.Net;

namespace AccionSocial.web.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly IAdministradorService _adminService;
        private readonly ILogger<AdminController> _logger;
        private readonly ITokenStorageService _tokenStorage;
        private readonly ITokenRefreshService _tokenRefreshService;

        public AdminController(
            IAdministradorService adminService,
            ILogger<AdminController> logger,
            ITokenStorageService tokenStorage,
            ITokenRefreshService tokenRefreshService)
        {
            _adminService = adminService;
            _logger = logger;
            _tokenStorage = tokenStorage;
            _tokenRefreshService = tokenRefreshService;
        }

        [HttpGet]
        public async Task<IActionResult> AdministracionUsuarios(
            int pagina = 1,
            int tamanoPagina = 10,
            string filtro = "",
            string sortOrder = "")
        {

            try
            {
                // Verificar tokens primero
                var token = await _tokenStorage.GetTokenAsync();
                var refreshToken = await _tokenStorage.GetRefreshTokenAsync();
                _logger.LogDebug("Token actual: {Token}", token != null ? "[presente]" : "null");
                _logger.LogDebug("Refresh token actual: {RefreshToken}", refreshToken != null ? "[presente]" : "null");


                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(refreshToken))
                {
                    _logger.LogWarning("Tokens no disponibles - redirigiendo a login");
                    return RedirectToLogin();
                }

                bool tokenValido = await _tokenRefreshService.TryRefreshTokenAsync();
                if (!tokenValido)
                {
                    _logger.LogWarning("No se pudo validar el token - redirigiendo a login");
                    return RedirectToLogin();
                }
                // Obtener roles primero
                var roles = await _adminService.ObtenerRolesAsync();
                ViewBag.Roles = roles;

                // Obtener usuarios paginados
                var usuariosPaginados = await _adminService.ObtenerUsuariosPaginados(pagina, tamanoPagina, filtro, sortOrder);

                var model = new AdminUsuariosViewModel
                {
                    Usuarios = usuariosPaginados ?? new PaginacionResponse<ListaUsuariosDTO>
                    {
                        Pagina = pagina,
                        TamanoPagina = tamanoPagina,
                        Total = 0,
                        Datos = new List<ListaUsuariosDTO>()
                    },
                    RegistroModel = new RegistroDTO() // Initialize if needed
                };



                // Configurar parámetros de ordenamiento para la vista
                ViewData["CurrentSort"] = sortOrder;
                ViewData["NameSortParam"] = string.IsNullOrEmpty(sortOrder) ? "name_desc" : "";
                ViewData["EmailSortParam"] = sortOrder == "email_asc" ? "email_desc" : "email_asc";
                ViewData["DateSortParam"] = sortOrder == "date_asc" ? "date_desc" : "date_asc";
                ViewData["CurrentFilter"] = filtro;

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en AdministracionUsuarios");

                bool refreshed = await _tokenRefreshService.TryRefreshTokenAsync();
                if (refreshed)
                {
                    return RedirectToAction(nameof(AdministracionUsuarios));
                }

                return RedirectToAction("Logout", "Auth");
            }
        }

        [HttpPost("registrar-usuario")] 
        public async Task<IActionResult> RegistrarUsuario(RegistroDTO registerDto) 
        {
            try
            {
                _logger.LogInformation("Iniciando registro de nuevo usuario");
                _logger.LogDebug("Datos recibidos: {@RegisterDto}", registerDto);

                bool tokenValido = await _tokenRefreshService.TryRefreshTokenAsync();
                if (!tokenValido)
                {
                    _logger.LogWarning("No se pudo validar el token - redirigiendo a login");
                    return RedirectToLogin();
                }

                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage)
                        .ToList();

                    _logger.LogWarning("Datos de registro inválidos. Errores: {@Errors}", errors);

                    return BadRequest(new ResultadoDTO
                    {
                        Success = false,
                        Message = "Datos inválidos",
                        Errors = errors
                    });
                }


                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage)
                        .ToList();

                    _logger.LogWarning("Datos de registro inválidos. Errores: {@Errors}", errors);

                    // Devuelve los errores como JSON
                    return Json(new ResultadoDTO
                    {
                        Success = false,
                        Message = "Datos inválidos",
                        Errors = errors
                    });
                }


                var result = await _adminService.RegistrarUsuarioAsync(registerDto);

                if (result.Success)
                {
                    _logger.LogInformation($"Usuario {registerDto.Email} registrado exitosamente");
                    return Ok(result);
                }

                _logger.LogWarning("Error al registrar usuario: {Errores}", result.Errors);
                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al registrar usuario");
                ModelState.AddModelError("", "Error interno del servidor");
                return Json(new ResultadoDTO
                {
                    Success = false,
                    Message = "Error interno",
                    Errors = new List<string> { ex.Message }
                });
            }

        }
        private IActionResult RedirectToLogin()
        {
            return RedirectToAction("Login", "Login", new { returnUrl = Url.Action() });
        }
    }
}
