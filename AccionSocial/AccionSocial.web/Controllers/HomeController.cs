using AccionSocial.web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AccionSocial.web.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult RegistrarTaller()
        {
            return View();
        }
        public IActionResult Reportes()
        {
            return View();
        }
        public IActionResult QRAsistencia()
        {
            return View();
        }
        [HttpGet]
    public IActionResult RegistrarAsistencia(string idParticipante, int idTaller)
    {
        // Aquí haces la lógica para registrar en base de datos:
        // Ejemplo:
        // _dbContext.Asistencias.Add(new Asistencia { ParticipanteId = idParticipante, TallerId = idTaller, Fecha = DateTime.Now });
        // _dbContext.SaveChanges();

        // Retornar una vista muy simple con el pop-up o mensaje
        ViewData["IdParticipante"] = idParticipante;
        ViewData["IdTaller"] = idTaller;
        return View();
    }
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
