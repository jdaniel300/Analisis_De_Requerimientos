using AccionSocial.web.Services.Auth;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace AccionSocial.web.Controllers
{
    public class LoginController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<LoginController> _logger;

        public LoginController(
           IAuthService authService,
           IHttpClientFactory httpClientFactory,
           IConfiguration configuration,
           ILogger<LoginController> logger)
        {
            _authService = authService;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View("_Login"); ;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDTO model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return PartialView("_Login", model);
            }

            try
            {

                var response = await LoginViaApi(model);

                // Crear la identidad del usuario
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, response.Username),
                    new Claim(ClaimTypes.Name, response.Username),
                    new Claim(ClaimTypes.Email, response.Email),
                    new Claim("FullName", response.NombreCompleto)
                };

                foreach (var role in response.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = model.RememberMe,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7),
                    AllowRefresh = true,
                    IssuedUtc = DateTimeOffset.UtcNow
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                _logger.LogInformation("Usuario {Username} ha iniciado sesión correctamente", response.Username);

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }
                return RedirectToAction("Index", "Home");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning("Intento de inicio de sesión fallido: {Message}", ex.Message);
                ModelState.AddModelError(string.Empty, "Credenciales inválidas");
                return PartialView("_Login", model); // Cambiado de View a PartialView
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al iniciar sesión");
                ModelState.AddModelError(string.Empty, "Ocurrió un error al iniciar sesión");
                return PartialView("_Login", model); // Cambiado de View a PartialView
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string timeout = null)
        {
            try
            {
                // Llama al servicio para hacer logout en el API
                await _authService.LogoutAsync();

                // Limpia la autenticación local
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Manejo específico para cierre por inactividad
                if (!string.IsNullOrEmpty(timeout) && timeout == "true")
                {
                    TempData["TimeoutMessage"] = "Tu sesión ha expirado por inactividad. Por favor inicia sesión nuevamente.";
                }

                return RedirectToAction("Login", "Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cerrar sesión");
                TempData["ErrorMessage"] = "Ocurrió un error al cerrar la sesión";
                return RedirectToAction("Index", "Home");
            }
        }

        private async Task<LoginResponse> LoginViaApi(LoginDTO model)
        {
            var client = _httpClientFactory.CreateClient();
            var apiUrl = _configuration["ApiSettings:BaseUrl"] + "/auth/login";

            // Agregar headers
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var request = new HttpRequestMessage(HttpMethod.Post, apiUrl)
            {
                Content = JsonContent.Create(model)
            };

            var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError($"Error en login: {response.StatusCode} - {errorContent}");
                throw new UnauthorizedAccessException("Credenciales inválidas");
            }

            return await response.Content.ReadFromJsonAsync<LoginResponse>();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View("_Registro", new RegistroDTO());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegistroDTO model)
        {
            if (!ModelState.IsValid)
            {
                return View("_Registro", model);
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var apiUrl = _configuration["ApiSettings:BaseUrl"] + "/auth/register";

                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.PostAsJsonAsync(apiUrl, model);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    ModelState.AddModelError(string.Empty, errorContent);
                    return View("_Registro", model);
                }

                TempData["SuccessMessage"] = "¡Registro exitoso! Por favor inicia sesión.";
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el registro");
                ModelState.AddModelError(string.Empty, "Ocurrió un error durante el registro. Por favor inténtalo de nuevo.");
                return View("_Registro", model);
            }
        }

    }
}

