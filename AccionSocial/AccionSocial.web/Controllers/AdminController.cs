using AccionSocial.web.Models;
using AccionSocial.web.Services.Admin;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace AccionSocial.web.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly IAdministradorService _adminService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            IAdministradorService adminService,
            ILogger<AdminController> logger)
        {
            _adminService = adminService;
            _logger = logger;
        }

        public async Task<IActionResult> AdministracionUsuarios(
            string sortOrder,
            string currentFilter,
            string searchString,
            int? pageNumber,
            string selectedUserId,
            string editUserId,
            string deleteUserId)
        {
            try
            {
                // Configurar parámetros de ordenación
                ViewData["CurrentSort"] = sortOrder;
                ViewData["NameSortParam"] = string.IsNullOrEmpty(sortOrder) ? "name_desc" : "";
                ViewData["EmailSortParam"] = sortOrder == "email_asc" ? "email_desc" : "email_asc";
                ViewData["DateSortParam"] = sortOrder == "date_asc" ? "date_desc" : "date_asc";

                // Manejar búsqueda y paginación
                searchString = searchString ?? currentFilter;
                if (!string.IsNullOrEmpty(searchString))
                {
                    pageNumber = 1;
                }

                ViewData["CurrentFilter"] = searchString;

                // Obtener usuarios paginados
                int pageSize = 10;
                PaginacionResponse<ListaUsuariosDTO> usuarios;

                try
                {
                    usuarios = await _adminService.ObtenerUsuariosPaginados(
                        pageNumber ?? 1,
                        pageSize,
                        searchString ?? "",
                        sortOrder ?? "");

                    // Si no hay datos, inicializar una lista vacía
                    usuarios.Datos ??= new List<ListaUsuariosDTO>();
                }
                catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    _logger.LogError(ex, "Endpoint de usuarios no encontrado");
                    ModelState.AddModelError("", "El servicio de usuarios no está disponible temporalmente");

                    usuarios = new PaginacionResponse<ListaUsuariosDTO>
                    {
                        Pagina = pageNumber ?? 1,
                        TamanoPagina = pageSize,
                        Total = 0,
                        Datos = new List<ListaUsuariosDTO>()
                    };
                }
                catch (UnauthorizedAccessException)
                {
                    _logger.LogWarning("Acceso no autorizado al servicio de administración");
                    return RedirectToAction("Login", "Login");
                }

                // Configurar ViewData para la paginación
                ViewData["TotalPaginas"] = (int)Math.Ceiling(usuarios.Total / (double)usuarios.TamanoPagina);
                ViewData["PaginaActual"] = usuarios.Pagina;
                ViewData["TotalRegistros"] = usuarios.Total;

                // Manejar paneles de detalles/edición/eliminación
                var viewBags = new
                {
                    ShowDetails = !string.IsNullOrEmpty(selectedUserId),
                    ShowEditPanel = !string.IsNullOrEmpty(editUserId),
                    ShowDeletePanel = !string.IsNullOrEmpty(deleteUserId)
                };

                ViewBag.ShowDetails = viewBags.ShowDetails;
                ViewBag.ShowEditPanel = viewBags.ShowEditPanel;
                ViewBag.ShowDeletePanel = viewBags.ShowDeletePanel;

                if (viewBags.ShowDetails)
                {
                    ViewBag.SelectedUser = usuarios.Datos.FirstOrDefault(u => u.Id.ToString() == selectedUserId);
                }
                else if (viewBags.ShowEditPanel)
                {
                    ViewBag.UserToEdit = usuarios.Datos.FirstOrDefault(u => u.Id.ToString() == editUserId);
                }
                else if (viewBags.ShowDeletePanel)
                {
                    ViewBag.UserToDelete = usuarios.Datos.FirstOrDefault(u => u.Id.ToString() == deleteUserId);
                }

                return View(usuarios);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error crítico en la administración de usuarios");
                return RedirectToAction("Error", "Home", new { message = "Ocurrió un error inesperado" });
            }
        }
    }
}
