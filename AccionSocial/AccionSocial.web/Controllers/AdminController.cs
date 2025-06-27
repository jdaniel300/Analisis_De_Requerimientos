using AccionSocial.web.Models;
using AccionSocial.web.Services.Admin;
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

        public AdminController(
            IAdministradorService adminService,
            ILogger<AdminController> logger)
        {
            _adminService = adminService;
            _logger = logger;
        }

        public async Task<IActionResult> AdministracionUsuarios(
            int pagina = 1,
            int tamanoPagina = 10,
            string filtro = "",
            string sortOrder = "")
        {
            try
            {
                var model = await _adminService.ObtenerUsuariosPaginados(pagina, tamanoPagina, filtro, sortOrder);

                if (model?.Datos == null)
                {
                    _logger.LogWarning("Received null data from service");
                    model = new PaginacionResponse<ListaUsuariosDTO>
                    {
                        Pagina = pagina,
                        TamanoPagina = tamanoPagina,
                        Total = 0,
                        Datos = new List<ListaUsuariosDTO>()
                    };
                }

                // Add sorting parameters for view
                ViewData["CurrentSort"] = sortOrder;
                ViewData["NameSortParam"] = string.IsNullOrEmpty(sortOrder) ? "name_desc" : "";
                ViewData["EmailSortParam"] = sortOrder == "email_asc" ? "email_desc" : "email_asc";
                ViewData["DateSortParam"] = sortOrder == "date_asc" ? "date_desc" : "date_asc";
                ViewData["CurrentFilter"] = filtro;

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading user administration");
                return View("Error", new ErrorViewModel
                {
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
                });
            }

        }
        [HttpPost("registrar-usuario")]
        public async Task<IActionResult> RegistrarUsuario([FromBody] RegistroDTO registerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ResultadoDTO
                {
                    Success = false,
                    Message = "Datos inválidos",
                    Errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage)
                        .ToList()
                });
            }

            var result = await _adminService.RegistrarUsuarioAsync(registerDto);

            if (result.Success)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }
    }
}
