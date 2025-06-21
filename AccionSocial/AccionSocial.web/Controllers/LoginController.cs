using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace AccionSocial.web.Controllers
{
    public class LoginController : Controller
    {
        private readonly IAuthService _authService;
        private readonly ITokenStorageService _tokenStorage;
        private readonly ILogger<LoginController> _logger;

        public LoginController(
            IAuthService authService,
            ITokenStorageService tokenStorage,
            ILogger<LoginController> logger)
        {
            _authService = authService;
            _tokenStorage = tokenStorage;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View("_Login");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDTO model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View("_Login", model);

            try
            {
                var response = await _authService.AuthenticateAsync(model);

                if (response == null || string.IsNullOrEmpty(response.Token))
                {
                    ModelState.AddModelError(string.Empty, "Invalid authentication response");
                    return View("_Login", model);
                }

                // Store token in both storage mechanisms
                await _tokenStorage.SetTokenAsync(response.Token);

                // Create authentication cookie
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, response.User.userName),
                    new Claim(ClaimTypes.Name, response.User.userName),
                    new Claim(ClaimTypes.Email, response.User.email ?? string.Empty),
                    new Claim("FullName", response.User.nombreCompleto ?? string.Empty)
                };

                if (response.User.roles != null)
                {
                    claims.AddRange(response.User.roles.Select(role =>
                        new Claim(ClaimTypes.Role, role)));
                }

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = model.RememberMe,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7),
                    AllowRefresh = true
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(new ClaimsIdentity(
                        claims,
                        CookieAuthenticationDefaults.AuthenticationScheme)),
                    authProperties);

                return RedirectToLocal(returnUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed");
                ModelState.AddModelError(string.Empty, "Login failed. Please try again.");
                return View("_Login", model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await _tokenStorage.RemoveTokenAsync();
            return RedirectToAction("Index", "Home");
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
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
                // Usar el servicio de autenticación en lugar de llamar directamente a la API
                var response = await _authService.RegisterAsync(model);

                // Si el registro incluye autologin (tiene token)
                if (!string.IsNullOrEmpty(response?.Token))
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.UserName),
                        new Claim(ClaimTypes.Email, model.Email),
                        new Claim("FullName", $"{model.Nombre} {model.Apellidos}"),
                        new Claim("JwtToken", response.Token)
                    };

                    if (!string.IsNullOrEmpty(model.Rol))
                    {
                        claims.Add(new Claim(ClaimTypes.Role, model.Rol));
                    }

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                        new AuthenticationProperties
                        {
                            IsPersistent = false,
                            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                        });

                    TempData["SuccessMessage"] = "¡Registro y autenticación exitosos!";
                    return RedirectToAction("Index", "Home");
                }

                TempData["SuccessMessage"] = "¡Registro exitoso! Por favor inicia sesión.";
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el registro");

                // Manejar errores de validación del API
                if (ex.Message.Contains("Error en el registro") && ex.InnerException is JsonException)
                {
                    ModelState.AddModelError(string.Empty, "Error en los datos proporcionados");
                }
                else
                {
                    ModelState.AddModelError(string.Empty,
                        !string.IsNullOrEmpty(ex.Message) ? ex.Message : "Ocurrió un error durante el registro. Por favor inténtalo de nuevo.");
                }

                return View("_Registro", model);
            }
        }
    }
}

