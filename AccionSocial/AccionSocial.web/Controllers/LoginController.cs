using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using static AuthService;

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

        private static readonly ConcurrentDictionary<string, (int Attempts,        DateTime LastAttempt)> FailedAttempts = new();
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDTO model, string returnUrl = null)
        {
            // Verificación de intentos fallidos
            if (FailedAttempts.TryGetValue(model.UsernameOrEmail, out var attemptInfo))
            {
                if (attemptInfo.Attempts >= 3)
                {
                    var delaySeconds = Math.Min(30, attemptInfo.Attempts * 2);
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds));

                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new
                        {
                            message = $"Demasiados intentos. Espere {delaySeconds} segundos.",
                            shouldRefresh = true
                        }, HttpStatusCode.TooManyRequests);
                    }

                    ModelState.AddModelError(string.Empty, $"Demasiados intentos. Espere {delaySeconds} segundos.");
                    return View("_Login", model);
                }
            }

            try
            {
                await _tokenStorage.ClearTokenAsync();
                var response = await _authService.AuthenticateAsync(model);
                FailedAttempts.TryRemove(model.UsernameOrEmail, out _);

                if (response == null || string.IsNullOrEmpty(response.Token))
                {
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        await _tokenStorage.ClearTokenAsync();
                        return Unauthorized(new { message = "Credenciales inválidas" });
                    }

                    ModelState.AddModelError(string.Empty, "Invalid authentication response");
                    return View("_Login", model);
                }

                // Almacenar tokens
                await _tokenStorage.SetTokenAsync(response.Token);
                await _tokenStorage.SetRefreshTokenAsync(response.RefreshToken);

                // Crear identidad
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

                // Manejo de redirección
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new
                    {
                        redirectUrl = Url.IsLocalUrl(returnUrl) ? returnUrl : "/Home"
                    });
                }

                return RedirectToLocal(returnUrl);
            }
            catch (AuthException ex) when (ex.ErrorType == AuthErrorType.InvalidCredentials)
            {
                var attemptsInfo = FailedAttempts.AddOrUpdate(model.UsernameOrEmail,
                    (1, DateTime.UtcNow),
                    (key, oldValue) => (oldValue.Attempts + 1, DateTime.UtcNow));

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new
                    {
                        message = ex.Message,
                        shouldRefresh = attemptsInfo.Attempts >= 3,
                        remainingAttempts = 5 - attemptsInfo.Attempts
                    }, HttpStatusCode.Unauthorized);
                }

                ModelState.AddModelError(string.Empty, ex.Message);
                return View("_Login", model);
            }
            catch (AuthException ex) when (ex.ErrorType == AuthErrorType.AccountLocked)
            {
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { message = ex.Message }, HttpStatusCode.Forbidden);
                }

                ModelState.AddModelError(string.Empty, ex.Message);
                return View("_Login", model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el login");

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { message = "Error interno del servidor" }, HttpStatusCode.InternalServerError);
                }

                ModelState.AddModelError(string.Empty, "Error interno del servidor");
                return View("_Login", model);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await _tokenStorage.RemoveTokenAsync();
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

