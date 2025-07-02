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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegistrarUsuario(RegistroDTO model)
        {
            try
            {
                _logger.LogInformation("Iniciando registro de nuevo usuario");
                _logger.LogDebug("Datos recibidos: {@RegisterDto}", model);

                bool tokenValido = await _tokenRefreshService.TryRefreshTokenAsync();
                if (!tokenValido)
                {
                    _logger.LogWarning("No se pudo validar el token - redirigiendo a login");
                    return Json(new
                    {
                        success = false,
                        message = "Sesión expirada",
                        errors = new Dictionary<string, string[]> {
                    { "General", new[] { "Su sesión ha expirado, por favor inicie sesión nuevamente" } }
                }
                    });
                }

                if (!ModelState.IsValid)
                {
                    var errors = new Dictionary<string, string[]>();
                    foreach (var key in ModelState.Keys)
                    {
                        var state = ModelState[key];
                        if (state.Errors.Count > 0)
                        {
                            // Simplificar el nombre de la clave para que coincida con el frontend
                            var simplifiedKey = key.Replace("RegistroModel.", "");
                            errors[simplifiedKey] = state.Errors.Select(e => e.ErrorMessage).ToArray();
                        }
                    }

                    return Json(new { success = false, errors = errors });
                }

                var result = await _adminService.RegistrarUsuarioAsync(model);

                if (result.Success)
                {
                    _logger.LogInformation($"Usuario {model.Email} registrado exitosamente");
                    return Json(new
                    {
                        success = true,
                        message = result.Message ?? "Usuario registrado correctamente"
                    });
                }

                _logger.LogWarning("Error al registrar usuario: {Errores}", result.Errors);

                // Convertir los errores a un formato compatible
                var errorDict = new Dictionary<string, string[]>();
                if (result.Errors != null && result.Errors.Any())
                {
                    errorDict["General"] = result.Errors.ToArray();
                }

                return Json(new
                {
                    success = false,
                    message = result.Message ?? "Error al registrar usuario",
                    errors = errorDict
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al registrar usuario");
                return Json(new
                {
                    success = false,
                    message = "Error interno del servidor",
                    errors = new Dictionary<string, string[]> {
                { "General", new[] { ex.Message } }
            }
                });
            }
        }
        private IActionResult RedirectToLogin()
        {
            return RedirectToAction("Login", "Login", new { returnUrl = Url.Action() });
        }
    }
}
