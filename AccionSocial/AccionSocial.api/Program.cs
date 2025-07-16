using AccionSocial.api.Services.Token;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Relaciones;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.CodeAnalysis.Elfie.Serialization;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
/* ==================== CONFIGURACIÓN BÁSICA ==================== */

builder.Services.AddControllers();
builder.Services.AddMemoryCache();
builder.Services.AddHttpContextAccessor();
builder.Services.AddEndpointsApiExplorer();

/* ==================== CONFIGURACIÓN DEL SERVIDOR ==================== */
// Configuración de Kestrel
builder.WebHost.ConfigureKestrel(serverOptions => {
    serverOptions.Limits.MaxConcurrentConnections = 100;
    serverOptions.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
    serverOptions.ListenAnyIP(8081);
});

/* ==================== BASE DE DATOS E IDENTITY ==================== */
// Configuración de DbContext con Identity
var conn = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<MyIdentityDbContext>(options =>
    options.UseSqlServer(conn, b => b.MigrationsAssembly("AccionSocialModels")));

// Configuración de Identity con soporte para Roles
builder.Services.AddIdentity<Usuario, Rol>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<MyIdentityDbContext>()
.AddRoles<Rol>()
.AddDefaultTokenProviders();

/* ==================== SEGURIDAD Y AUTENTICACIÓN ==================== */
// Configuración de DataProtection
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .SetApplicationName("AccionSocial");

// Configuración de JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
// Registro del servicio de tokens
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ClockSkew = TimeSpan.Zero,
        NameClaimType = ClaimTypes.NameIdentifier,
        RoleClaimType = ClaimTypes.Role
    };

    // For older tokens that might have string IDs
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var userIdClaim = context.Principal.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim != null && !int.TryParse(userIdClaim.Value, out _))
            {
                context.Fail("Invalid user ID format");
            }

        },

        OnAuthenticationFailed = context =>
        {
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers.Add("Token-Expired", "true");
            }
            return Task.CompletedTask;
        }
    };
})
.AddCookie();

builder.Services.AddAuthorization(options =>
{
    // Define la política "Admin" que requiere el rol "Admin"
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));

    // Opcional: Otras políticas que necesites
    // options.AddPolicy("OtroRol", policy => policy.RequireRole("OtroRol"));
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowWebApp", builder => builder
        .WithOrigins(
            "http://localhost:8090",
            "http://accionsocial.web:8080" // Note container port
        )
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials()
        .SetPreflightMaxAge(TimeSpan.FromMinutes(10))
    );
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.SameAsRequest;
});

/* ==================== COMPRESIÓN Y SWAGGER ==================== */
// Añadir compresión de respuesta
builder.Services.AddResponseCompression(options => {
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AccionSocial API",
        Version = "v1",
        Description = "API para el sistema AccionSocial"
    });

    // Asegúrate de incluir los esquemas de seguridad
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Incluye los comentarios XML si los tienes
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

/* ==================== COMPORTAMIENTO DE LA API ==================== */

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = false;
});



/* ==================== CONSTRUCCIÓN DE LA APLICACIÓN ==================== */
var app = builder.Build();

// Configuración del pipeline de solicitudes HTTP
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AccionSocial API V1"));
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    // app.UseHttpsRedirection(); // Descomentar en producción
}

app.UseResponseCompression();
app.UseStaticFiles();
app.UseRouting();


app.Use(async (context, next) =>
{
    context.Response.Headers.Append("Access-Control-Allow-Origin", "http://accionsocial.web:8080");
    context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");

    if (context.Request.Method == "OPTIONS")
    {
        context.Response.StatusCode = 204;
        await context.Response.CompleteAsync();
        return;
    }

    await next();
});

app.UseCors("AllowWebApp");
app.UseAuthentication();
app.UseAuthorization();

// Configuración para servir archivos estáticos
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.ContentRootPath, "wwwroot")),
    RequestPath = ""
});


// Configuración para servir archivos estáticos
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.ContentRootPath, "uploads")),
    RequestPath = "/uploads",
    ContentTypeProvider = new FileExtensionContentTypeProvider()
});

/* ==================== INICIALIZACIÓN DE LA BASE DE DATOS ==================== */
await InitializeDatabase(app);


/* ==================== ENDPOINTS ==================== */
var authGroup = app.MapGroup("/api/auth").WithTags("Autenticacion");
ConfigureAuthEndpoints(authGroup);

var usrGroup = app.MapGroup("/api/usr").WithTags("Usuario");
ConfigureUsrEndpoints(usrGroup);

var consGroup = app.MapGroup("/api/consultas").WithTags("Consultas");
ConfigureConsultaEndpoints(consGroup);

var filesGroup = app.MapGroup("/api/files").WithTags("Archivos");
ConfigureFileEndpoints(filesGroup);

var modGroup = app.MapGroup("/api/mod").WithTags("Modificaciones");
ConfigureModificacionEndpoints(modGroup);

var tallerGroup = app.MapGroup("/api/taller").WithTags("Talleres");
ConfigureTalleresEndpoints(tallerGroup);



//--------------------PUEBAS------------------------>
// PARA PRUEBAS -> Ejemplo de endpoint protegido 
app.MapGet("/api/protected", (ClaimsPrincipal user) =>
{
    return $"Hola {user.Identity?.Name}, este es un endpoint protegido!";
})
.RequireAuthorization()
.WithName("ProtectedEndpoint")
.WithOpenApi();

//PARA PRUEBAS -> Ejemplo de endpoint protegido con rol
app.MapGet("/api/admin-only", (ClaimsPrincipal user) =>
{
    return $"Hola {user.Identity?.Name}, este endpoint es solo para admins!";
})
.RequireAuthorization("Admin")
.WithName("AdminOnlyEndpoint")
.WithOpenApi();
//PARA PRUEBAS
app.MapGet("/api/test", () => "Funciona!");

app.Run();


/* ==================== MÉTODOS AUXILIARES ==================== */
async Task InitializeDatabase(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<Program>>();
    const int maxRetryAttempts = 10;
    var pauseBetweenFailures = TimeSpan.FromSeconds(5);

    for (int i = 0; i < maxRetryAttempts; i++)
    {
        try
        {
            logger.LogInformation("Database initialization attempt {AttemptNumber}", i + 1);

            var dbContext = services.GetRequiredService<MyIdentityDbContext>();

            // Verificar/Crear base de datos
            if (await dbContext.Database.CanConnectAsync())
            {
                var pendingMigrations = await dbContext.Database.GetPendingMigrationsAsync();
                if (pendingMigrations.Any())
                {
                    logger.LogInformation("Applying {Count} pending migrations...", pendingMigrations.Count());
                    await dbContext.Database.MigrateAsync();
                }
            }
            else
            {
                logger.LogInformation("Creating database and applying migrations...");
                await dbContext.Database.MigrateAsync();
            }

            // Inicialización de roles y usuarios
            await InitializeRolesAndAdminUser(services, logger);
            break;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Database initialization failed on attempt {AttemptNumber}", i + 1);

            if (i == maxRetryAttempts - 1)
            {
                logger.LogCritical("Max database initialization attempts reached");
                throw;
            }

            await Task.Delay(pauseBetweenFailures);
        }
    }
}

async Task InitializeRolesAndAdminUser(IServiceProvider services, ILogger<Program> logger)
{
    var roleManager = services.GetRequiredService<RoleManager<Rol>>();
    var userManager = services.GetRequiredService<UserManager<Usuario>>();

    // Roles a crear
    var roles = new[] { "Admin", "Staff", "Participante" };

    foreach (var roleName in roles)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new Rol { Name = roleName });
            logger.LogInformation("Created role: {RoleName}", roleName);
        }
    }

    // Buscar usuario admin
    var adminUser = await userManager.FindByNameAsync("admin");

    // Si no existe, crearlo
    if (adminUser == null)
    {
        adminUser = new Usuario
        {
            UserName = "admin",
            NormalizedUserName = "ADMIN",
            Email = "admin@accionsocial.com",
            NormalizedEmail = "ADMIN@ACCIONSOCIAL.COM",
            EmailConfirmed = true,
            Nombre = "Admin",
            Apellidos = "Sistema",
            PhoneNumber = "1234-5678",
            FechaCreacion = DateTime.Now,
            Estado = true,
            FechaCaducidadContrasena = DateOnly.FromDateTime(DateTime.Now.AddYears(1)),
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var createResult = await userManager.CreateAsync(adminUser, "AdminAccion123!");

        if (!createResult.Succeeded)
        {
            logger.LogError("Failed to create admin user: {Errors}",
                string.Join(", ", createResult.Errors.Select(e => e.Description)));
            return;
        }

        // Volver a cargar el usuario para asegurar que tiene ID permanente
        adminUser = await userManager.FindByNameAsync("admin");
        if (adminUser == null)
        {
            logger.LogError("Admin user was created but cannot be found");
            return;
        }
    }

    // Asignar rol solo si no lo tiene
    if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
    {
        var addRoleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
        if (!addRoleResult.Succeeded)
        {
            logger.LogError("Failed to add Admin role: {Errors}",
                string.Join(", ", addRoleResult.Errors.Select(e => e.Description)));
        }
        else
        {
            logger.LogInformation("Admin role assigned successfully");
        }
    }
}

void ConfigureFileEndpoints(RouteGroupBuilder group) {
    

    // Endpoint para subir archivos
    group.MapPost("/upload", async (HttpContext httpContext, IWebHostEnvironment env) =>
    {
        try
        {
            var formFile = httpContext.Request.Form.Files.FirstOrDefault();
            if (formFile == null || formFile.Length == 0)
                return Results.BadRequest("No se proporcionó archivo");

            // Validaciones
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".docx" };
            var fileExtension = Path.GetExtension(formFile.FileName).ToLower();
            if (!allowedExtensions.Contains(fileExtension))
                return Results.BadRequest("Tipo de archivo no permitido");

            if (formFile.Length > 10 * 1024 * 1024) // 10MB
                return Results.BadRequest("El archivo no debe superar los 10MB");

            // Crear directorio si no existe
            var uploadsPath = Path.Combine(env.ContentRootPath, "uploads");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            // Nombre único para el archivo
            var fileName = $"{Guid.NewGuid()}{fileExtension}";
            var filePath = Path.Combine(uploadsPath, fileName);

            // Guardar archivo
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await formFile.CopyToAsync(stream);
            }

            // Retornar URL relativa
            var fileUrl = $"/uploads/{fileName}";
            return Results.Ok(new { path = fileUrl, fileName = formFile.FileName });
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error al subir archivo: {ex.Message}");
        }
    }).RequireAuthorization(); // Opcional: proteger el endpoint

    // Endpoint para descargar/ver archivos
    group.MapGet("/download/{fileName}", (string fileName, IWebHostEnvironment env) =>
    {
        try
        {
            var filePath = Path.Combine(env.ContentRootPath, "uploads", fileName);

            if (!System.IO.File.Exists(filePath))
                return Results.NotFound();

            var provider = new FileExtensionContentTypeProvider();
            if (!provider.TryGetContentType(fileName, out var contentType))
            {
                contentType = "application/octet-stream";
            }

            return Results.File(filePath, contentType, fileDownloadName: fileName);
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error al obtener archivo: {ex.Message}");
        }
    });
}
//AHUTENTICACION
void ConfigureAuthEndpoints(RouteGroupBuilder group)
{
    // Login - PROBADO
    group.MapPost("/login", async (
    [FromBody] LoginDTO request,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] SignInManager<Usuario> signInManager,
    [FromServices] ITokenService tokenService,
    [FromServices] IOptions<JwtSettings> jwtSettings,
    [FromServices] ILogger<Program> logger) =>
    {
        // Validación del modelo
        if (string.IsNullOrWhiteSpace(request.UsernameOrEmail) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            logger.LogWarning("Intento de login con campos vacíos");
            return Results.Problem(
                title: "Datos inválidos",
                detail: "Usuario/Email y contraseña son requeridos",
                statusCode: StatusCodes.Status400BadRequest);
        }

        try
        {
            // 1. Buscar usuario - Mejorado para evitar consultas innecesarias
            var user = await userManager.Users
                .FirstOrDefaultAsync(u =>
                    (u.NormalizedEmail == request.UsernameOrEmail.ToUpper()) ||
                    (u.NormalizedUserName == request.UsernameOrEmail.ToUpper()));

            if (user == null || !user.Estado)
            {
                logger.LogWarning("Intento de login fallido para {UsernameOrEmail}", request.UsernameOrEmail);
                // Respuesta genérica por seguridad
                return Results.Problem(
                    title: "Autenticación fallida",
                    detail: "Credenciales inválidas",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // 2. Verificar contraseña - Con manejo de bloqueo
            var result = await signInManager.PasswordSignInAsync(
                user.UserName,
                request.Password,
                isPersistent: request.RememberMe,
                lockoutOnFailure: true);

            var accessFailedCount = await userManager.GetAccessFailedCountAsync(user);
            var maxAttempts = userManager.Options.Lockout.MaxFailedAccessAttempts;
            var remainingAttempts = maxAttempts - accessFailedCount - 1;

            if (!result.Succeeded)
            {
                logger.LogWarning("Credenciales inválidas para usuario {UserId}", user.Id);
                return Results.Problem(
                    title: "Autenticación fallida",
                    detail: remainingAttempts > 0
                        ? $"Credenciales inválidas. Le quedan {remainingAttempts} intentos."
                        : "Credenciales inválidas. Su cuenta será bloqueada en el próximo intento fallido.",
                    statusCode: StatusCodes.Status401Unauthorized,
                    extensions: new Dictionary<string, object?>
                    {
                    {"remainingAttempts", remainingAttempts}
                    });
            }

            if (result.IsLockedOut)
            {
                var lockoutEnd = await userManager.GetLockoutEndDateAsync(user);
                var remainingLockoutTime = lockoutEnd - DateTimeOffset.UtcNow;

                logger.LogWarning("Cuenta bloqueada temporalmente para {UserId}", user.Id);
                return Results.Problem(
                    title: "Cuenta bloqueada",
                    detail: $"Demasiados intentos fallidos. Intente nuevamente en {remainingLockoutTime.Value.Minutes} minutos.",
                    statusCode: StatusCodes.Status403Forbidden,
                    extensions: new Dictionary<string, object?>
                    {
                     {"remainingTime",  remainingLockoutTime.Value.TotalMinutes},
                     {"retryAfter", remainingLockoutTime.Value.TotalSeconds}
                    });
            }
            // 3. Generar tokens - Con validación adicional
            var roles = await userManager.GetRolesAsync(user);
            if (roles == null || !roles.Any())
            {
                logger.LogWarning("Usuario {UserId} no tiene roles asignados", user.Id);
                roles = new List<string> { "Usuario" }; // Rol por defecto
            }

            var token = tokenService.GenerateJwtToken(user, roles);
            var refreshToken = tokenService.GenerateRefreshToken();

            // 4. Actualizar usuario - Con transacción
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(jwtSettings.Value.RefreshTokenExpireDays);
            user.UltimoAcceso = DateTime.Now;

            var updateResult = await userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                logger.LogError("Error al actualizar refresh token para {UserId}: {Errors}",
                    user.Id, string.Join(", ", updateResult.Errors));
                return Results.Problem(
                    title: "Error interno",
                    detail: "No se pudo completar el login",
                    statusCode: StatusCodes.Status500InternalServerError);
            }

            // 5. Preparar respuesta segura
            var response = new
            {
                Token = token,
                RefreshToken = refreshToken,
                User = new
                {
                    userId = user.Id,
                    userName = user.UserName,
                    email = user.Email,
                    nombreCompleto = $"{user.Nombre} {user.Apellidos}".Trim(),
                    roles = roles.ToList()
                },
                ExpiresIn = DateTime.UtcNow.AddMinutes(jwtSettings.Value.TokenExpireMinutes)
            };

            logger.LogInformation("Login exitoso para usuario");

            await signInManager.SignInAsync(user, request.RememberMe);
            return Results.Ok(response);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error inesperado durante el login para {UsernameOrEmail}", request.UsernameOrEmail);
            return Results.Problem(
                title: "Error interno",
                detail: "Ocurrió un error inesperado",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    })
      .WithName("Login")
      .WithOpenApi();
    //Refresh Token
    group.MapPost("/refresh-token", async (
    [FromBody] RefreshTokenRequest request,
    [FromServices] ITokenService tokenService,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] ILogger<Program> logger,
    [FromServices] IOptions<JwtSettings> jwtSettings) =>
    {
        try
        {
            // Validar que el token no esté invalidado
            if (await tokenService.IsTokenInvalidatedAsync(request.Token))
            {
                logger.LogWarning("Intento de refresh con token invalidado");
                return Results.Unauthorized();
            }

            // Validar el token principal (ignorando expiración)
            var principal = tokenService.GetPrincipalFromToken(request.Token);
            if (principal == null)
            {
                logger.LogWarning("Token principal inválido");
                return Results.Unauthorized();
            }

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                logger.LogWarning("Token no contiene userId");
                return Results.Unauthorized();
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null || user.RefreshToken != request.RefreshToken ||
                user.RefreshTokenExpiry <= DateTime.UtcNow)
            {
                logger.LogWarning("Refresh token no coincide o ha expirado");
                return Results.Unauthorized();
            }

            // Invalidar el token anterior
            await tokenService.InvalidateTokenAsync(request.Token);

            // Generar nuevo token
            var roles = await userManager.GetRolesAsync(user);
            var newToken = tokenService.GenerateJwtToken(user, roles);

            // Generar nuevo refresh token
            var newRefreshToken = tokenService.GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(jwtSettings.Value.RefreshTokenExpireDays);
            await userManager.UpdateAsync(user);

            logger.LogInformation("Token refrescado exitosamente para el usuario {UserId}", userId);

            return Results.Ok(new AuthResult
            {
                Token = newToken,
                RefreshToken = newRefreshToken
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error inesperado en el endpoint de refresh-token");
            return Results.Problem("Error interno del servidor");
        }
    })
      .WithName("RefreshToken")
      .WithOpenApi();
    // Logout - PROBADO
    group.MapPost("/logout", async (
    [FromServices] ITokenService tokenService,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] ILogger<Program> logger,
    HttpContext httpContext) =>
    {
        try
        {
            // Obtener el token del header Authorization
            var authHeader = httpContext.Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Results.Unauthorized();
            }
            var token = authHeader["Bearer ".Length..].Trim();

            // 1. Invalidar el token JWT (sin validarlo primero)
            var invalidationResult = await tokenService.InvalidateTokenAsync(token);
            if (!invalidationResult)
            {
                logger.LogWarning("No se pudo invalidar el token");
            }

            // 2. Limpiar el refresh token del usuario
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.RefreshToken = null;
                    user.RefreshTokenExpiry = null;
                    await userManager.UpdateAsync(user);
                }
            }

            // 3. Cerrar sesión de Identity
            await httpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            logger.LogInformation("Logout exitoso para usuario {UserId}", userId);
            return Results.Ok(new { message = "Sesión cerrada correctamente" });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error durante el logout");
            return Results.Problem(
                title: "Error interno",
                detail: "Ocurrió un error al cerrar la sesión",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    })
      .WithName("Logout")
      .WithOpenApi();

    //REGISTRO POR LOGIN - PROBADO
    group.MapPost("/register", async (
        RegistroDTO registerUserDto,
        UserManager<Usuario> userManager,
        ILogger<Program> logger) =>
    {
        // Validaciones básicas
        if (registerUserDto.Password != registerUserDto.ConfirmPassword)
        {
            return Results.BadRequest("Las contraseñas no coinciden.");
        }

        // Verificar si el usuario ya existe
        var existingUser = await userManager.FindByNameAsync(registerUserDto.UserName);
        if (existingUser != null)
        {
            return Results.BadRequest("El nombre de usuario ya está en uso.");
        }

        existingUser = await userManager.FindByEmailAsync(registerUserDto.Email);
        if (existingUser != null)
        {
            return Results.BadRequest("El correo electrónico ya está registrado.");
        }

        // Crear el nuevo usuario
        var user = new Usuario
        {
            UserName = registerUserDto.UserName,
            NormalizedUserName = registerUserDto.UserName.ToUpper(),
            Email = registerUserDto.Email,
            NormalizedEmail = registerUserDto.Email.ToUpper(),
            EmailConfirmed = false, // Puedes cambiar esto según tu lógica de negocio
            Nombre = registerUserDto.Nombre,
            Apellidos = registerUserDto.Apellidos,
            PhoneNumber = registerUserDto.PhoneNumber,
            FechaCreacion = DateTime.Now,
            Estado = true, // Puedes establecer esto según tu lógica de negocio
            FechaCaducidadContrasena = DateOnly.FromDateTime(DateTime.Now.AddYears(1)),
            SecurityStamp = Guid.NewGuid().ToString()
        };

        // Intentar crear el usuario
        var result = await userManager.CreateAsync(user, registerUserDto.Password);

        if (result.Succeeded)
        {
            var roleResult = await userManager.AddToRoleAsync(user, "Participante");
            logger.LogInformation("Nuevo usuario registrado: {UserName}", user.UserName);

            // Aquí puedes agregar lógica adicional como:
            // - Enviar email de confirmación
            // - Asignar roles por defecto
            // - Generar token de confirmación, etc.

            return Results.Ok(new { Message = "Usuario registrado exitosamente" });
        }
        else
        {
            var errors = result.Errors.Select(e => e.Description);
            logger.LogError("Error al registrar usuario: {Errors}", string.Join(", ", errors));
            return Results.BadRequest(new { Errors = errors });
        }
    }).WithName("RegisterUser").WithOpenApi();

    // REGISTRO POR ADMINISTRADOR - PROBADO
    group.MapPost("/admin/register", async (
        RegistroDTO registerUserDto,
        UserManager<Usuario> userManager,
        RoleManager<Rol> roleManager,
        IHttpContextAccessor httpContextAccessor,
        ILogger<Program> logger) =>
    {
        // Verificar si el usuario actual es admin
        var currentUser = await userManager.GetUserAsync(httpContextAccessor.HttpContext.User);
        if (currentUser == null || !(await userManager.IsInRoleAsync(currentUser, "Admin")))
        {
            return Results.Json(new
            {
                success = false,
                message = "No autorizado",
                errors = new List<string> { "No tiene permisos de administrador" }
            }, statusCode: 401);
        }

        // Validaciones básicas
        if (registerUserDto.Password != registerUserDto.ConfirmPassword)
        {
            return Results.Json(new
            {
                success = false,
                message = "Error de validación",
                errors = new List<string> { "Las contraseñas no coinciden." }
            }, statusCode: 400);
        }

        // Verificar si el usuario ya existe
        var existingUser = await userManager.FindByNameAsync(registerUserDto.UserName);
        if (existingUser != null)
        {
            return Results.Json(new
            {
                success = false,
                message = "Error de validación",
                errors = new List<string> { "El nombre de usuario ya está en uso." }
            }, statusCode: 400);
        }

        existingUser = await userManager.FindByEmailAsync(registerUserDto.Email);
        if (existingUser != null)
        {
            return Results.Json(new
            {
                success = false,
                message = "Error de validación",
                errors = new List<string> { "El correo electrónico ya está registrado." }
            }, statusCode: 400);
        }

        // Crear el nuevo usuario
        var user = new Usuario
        {
            UserName = registerUserDto.UserName,
            NormalizedUserName = registerUserDto.UserName.ToUpper(),
            Email = registerUserDto.Email,
            NormalizedEmail = registerUserDto.Email.ToUpper(),
            EmailConfirmed = true, // El admin puede confirmar emails directamente
            Nombre = registerUserDto.Nombre,
            Apellidos = registerUserDto.Apellidos,
            PhoneNumber = registerUserDto.PhoneNumber,
            FechaCreacion = DateTime.Now,
            Estado = true,
            FechaCaducidadContrasena = DateOnly.FromDateTime(DateTime.Now.AddYears(1)),
            SecurityStamp = Guid.NewGuid().ToString()
        };

        // Intentar crear el usuario
        var result = await userManager.CreateAsync(user, registerUserDto.Password);

        if (result.Succeeded)
        {
            // Verificar si se especificó un rol, si no, asignar "Participante" por defecto
            var roleName = !string.IsNullOrEmpty(registerUserDto.Rol) ?
                           registerUserDto.Rol : "Participante";

            // Verificar que el rol existe
            var roleExists = await roleManager.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                await userManager.DeleteAsync(user);
                return Results.BadRequest($"El rol {roleName} no existe.");
            }

            var roleResult = await userManager.AddToRoleAsync(user, roleName);

            if (!roleResult.Succeeded)
            {
                await userManager.DeleteAsync(user);
                logger.LogError("Error al asignar rol: {Errors}",
                    string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                return Results.BadRequest(new { Errors = roleResult.Errors });
            }

            logger.LogInformation("Nuevo usuario registrado por admin: {UserName} con rol {Role}",
                user.UserName, roleName);

            return Results.Ok(new
            {
                success = true,
                message = $"Usuario registrado exitosamente con rol {roleName}",
                data = new
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Role = roleName
                }
            });
        }
        else
        {
            var errors = result.Errors.Select(e => e.Description);
            logger.LogError("Error al registrar usuario: {Errors}", string.Join(", ", errors));
            return Results.BadRequest(new { Errors = errors });
        }
    }).WithName("RegisterUserByAdmin").WithOpenApi();
    //Obtener usuario por id admin - PROBADO
    group.MapGet("/admin/usuarios/{id}", async (
    [FromRoute] string id,
    [FromServices] UserManager<Usuario> userManager,
    ClaimsPrincipal userClaim) =>
    {
        var currentUser = await userManager.GetUserAsync(userClaim);
        var isAdmin = await userManager.IsInRoleAsync(currentUser, "Admin");

        // Si no es admin y no es su propio ID, denegar acceso
        if (!isAdmin && currentUser.Id.ToString() != id)
        {
            return Results.Forbid();
        }

        var user = await userManager.FindByIdAsync(id);
        if (user == null)
        {
            return Results.NotFound();
        }

        var roles = await userManager.GetRolesAsync(user);

        // Los admins ven todos los campos, los usuarios normales solo campos básicos
        return Results.Ok(isAdmin ? new
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            NombreCompleto = $"{user.Nombre} {user.Apellidos}",
            Roles = roles,
            Telefono = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            FechaCreacion = user.FechaCreacion // Campo personalizado ejemplo
        } : new
        {
            Id = user.Id,
            UserName = user.UserName,
            NombreCompleto = $"{user.Nombre} {user.Apellidos}"
        });
    }).WithName("UsuarioPorId").WithOpenApi();
}
//USUARIO
void ConfigureUsrEndpoints(RouteGroupBuilder group)
{
    //PROBADO
    group.MapGet("/usuarioActual", async (
        HttpContext httpContext,
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] ITokenService tokenService,
        [FromServices] ILogger<Program> logger) =>
    {
        try
        {
            // Obtener el claim del usuario desde el token JWT
            var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                logger.LogWarning("Intento de acceder a current-user sin autenticación");
                return Results.Unauthorized();
            }

            var userId = userIdClaim.Value;
            var user = await userManager.FindByIdAsync(userId);

            if (user == null || !user.Estado)
            {
                logger.LogWarning("Usuario no encontrado o inactivo: {UserId}", userId);
                return Results.NotFound("Usuario no encontrado o inactivo");
            }

            // Obtener roles del usuario
            var roles = await userManager.GetRolesAsync(user);
            if (roles == null || !roles.Any())
            {
                logger.LogWarning("Usuario {UserId} no tiene roles asignados", user.Id);
                roles = new List<string> { "Usuario" }; // Rol por defecto
            }

            // Preparar respuesta
            var response = new CurrentUserResponse(
                UserId: user.Id,
                UserName: user.UserName,
                Email: user.Email,
                Telefono: user.PhoneNumber,
                NombreCompleto: $"{user.Nombre} {user.Apellidos}".Trim(),
                Roles: roles.ToList(),
                FechaCreacion: user.FechaCreacion,
                UltimoAcceso: user.UltimoAcceso,
                Estado: user.Estado
            );


            logger.LogInformation("Información de usuario obtenida para {UserId}", user.Id);
            return Results.Ok(response);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error inesperado al obtener información del usuario actual");
            return Results.Problem(
                title: "Error interno",
                detail: "Ocurrió un error inesperado",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    })
      .WithName("UsuarioActual")
      .WithOpenApi()
      .RequireAuthorization();

    group.MapPost("/subirImagenPerfil", async (
    HttpContext httpContext,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] IWebHostEnvironment env,
    [FromServices] ILogger<Program> logger) =>
    {
        try
        {
            var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Results.Unauthorized();

            var formFile = httpContext.Request.Form.Files.FirstOrDefault();
            if (formFile == null || formFile.Length == 0)
                return Results.BadRequest("No se proporcionó archivo");

            // Validar tipo de archivo
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };
            var fileExtension = Path.GetExtension(formFile.FileName).ToLower();
            if (!allowedExtensions.Contains(fileExtension))
                return Results.BadRequest("Solo se permiten imágenes JPG, PNG, GIF o PDF");

            // Validar tamaño (max 10MB)
            if (formFile.Length > 10 * 1024 * 1024)
                return Results.BadRequest("El archivo no debe superar los 10MB");

            // Crear directorio si no existe
            var uploadsPath = Path.Combine(env.ContentRootPath, "uploads", "profile-images");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            // Nombre único para el archivo
            var fileName = $"{userIdClaim.Value}{fileExtension}";
            var filePath = Path.Combine(uploadsPath, fileName);

            // Guardar archivo
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await formFile.CopyToAsync(stream);
            }

            // Retornar URL relativa
            var imageUrl = $"/uploads/profile-images/{fileName}";
            return Results.Ok(new { imagePath = imageUrl });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al subir imagen de perfil");
            return Results.Problem("Error interno al procesar la imagen");
        }
    }).RequireAuthorization();

    group.MapGet("/obtenerImagenPerfil", async (
        HttpContext httpContext,
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] IWebHostEnvironment env,
        [FromServices] ILogger<Program> logger) =>
    {
        try
        {
            var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Results.Unauthorized();

            var uploadsPath = Path.Combine(env.ContentRootPath, "uploads", "profile-images");
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };

            // Buscar cualquier imagen con el ID de usuario como nombre
            foreach (var ext in allowedExtensions)
            {
                var filePath = Path.Combine(uploadsPath, $"{userIdClaim.Value}{ext}");
                if (System.IO.File.Exists(filePath))
                {
                    return Results.File(filePath, $"image/{ext.TrimStart('.')}");
                }
            }

            // Si no encuentra, retornar imagen por defecto
            var defaultImagePath = Path.Combine(env.WebRootPath, "img", "default-avatar.jpg");
            return Results.File(defaultImagePath, "image/jpeg");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al obtener imagen de perfil");
            var defaultImagePath = Path.Combine(env.WebRootPath, "img", "default-avatar.jpg");
            return Results.File(defaultImagePath, "image/jpeg");
        }
    }).RequireAuthorization();

    //Eliminar - PROBADO
    group.MapDelete("/usuarioActual", async (
    HttpContext httpContext,
    [FromBody] DeleteUserRequest request,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] SignInManager<Usuario> signInManager,
    [FromServices] ILogger<Program> logger) =>
    {
        try
        {
            // Obtener el usuario actual
            var currentUser = await userManager.GetUserAsync(httpContext.User);
            if (currentUser == null)
            {
                logger.LogWarning("Intento de eliminar cuenta sin autenticación");
                return Results.Unauthorized();
            }

            
            if (string.IsNullOrWhiteSpace(request.Password))
            {
                logger.LogWarning("Intento de eliminar cuenta sin proporcionar contraseña para el usuario {UserId}", currentUser.Id);
                return Results.BadRequest("Se requiere la contraseña para eliminar la cuenta");
            }

            // Verificar la contraseña
            var isPasswordValid = await userManager.CheckPasswordAsync(currentUser, request.Password);
            if (!isPasswordValid)
            {
                logger.LogWarning("Contraseña incorrecta al intentar eliminar la cuenta para el usuario {UserId}", currentUser.Id);
                return Results.BadRequest("Contraseña incorrecta");
            }

            // Eliminar el usuario
            var result = await userManager.DeleteAsync(currentUser);

            if (!result.Succeeded)
            {
                logger.LogError("Error al eliminar la cuenta del usuario {UserId}: {Errors}",
                    currentUser.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return Results.Problem(
                    detail: string.Join(", ", result.Errors.Select(e => e.Description)),
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Cerrar sesión después de eliminar la cuenta
            await signInManager.SignOutAsync();

            logger.LogInformation("Cuenta eliminada exitosamente para el usuario {UserId}", currentUser.Id);
            return Results.NoContent();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error inesperado al intentar eliminar la cuenta del usuario");
            return Results.Problem(
                title: "Error interno",
                detail: "Ocurrió un error inesperado al intentar eliminar la cuenta",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    })
    .WithName("EliminarUsuarioActual")
    .WithOpenApi()
    .RequireAuthorization();

    //Elimiar por id - PROBADO
    group.MapDelete("/eliminar/{id}", async (
        [FromRoute] string id,
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] SignInManager<Usuario> signInManager,
        ClaimsPrincipal userClaim) =>
    {
        // Verificar si el usuario actual es admin
        var currentUser = await userManager.GetUserAsync(userClaim);
        var isAdmin = await userManager.IsInRoleAsync(currentUser, "Admin");

        if (!isAdmin)
        {
            return Results.Forbid();
        }

        // No permitir auto-eliminación
        if (currentUser.Id.ToString() == id)
        {
            return Results.BadRequest("No puedes eliminarte a ti mismo.");
        }

        var userToDelete = await userManager.FindByIdAsync(id);
        if (userToDelete == null)
        {
            return Results.NotFound();
        }

        var result = await userManager.DeleteAsync(userToDelete);

        if (!result.Succeeded)
        {
            return Results.Problem(
                detail: string.Join(", ", result.Errors.Select(e => e.Description)),
                statusCode: StatusCodes.Status400BadRequest);
        }
        if (currentUser.Id.ToString() == id)
        {
            await signInManager.SignOutAsync();
        }

        return Results.NoContent();
    }).RequireAuthorization(policy => policy.RequireRole("Admin"))
      .WithName("EliminarUsuarioPorIdAdmin")
      .WithOpenApi();

    //Actrualizar usuario - PROBADO
    group.MapPut("/actualizarUsuario/{id}", async (
    [FromRoute] int id,
    [FromBody] UsuarioUpdateDto updateDto,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] SignInManager<Usuario> signInManager,
    ClaimsPrincipal userClaim) =>
    {
        // Obtener usuario actual (el que hace la solicitud)
        var currentUser = await userManager.GetUserAsync(userClaim);
        if (currentUser == null) return Results.Unauthorized();

        // Obtener usuario a modificar
        var userToUpdate = await userManager.FindByIdAsync(id.ToString());
        if (userToUpdate == null) return Results.NotFound();

        // Verificar permisos
        var isAdmin = await userManager.IsInRoleAsync(currentUser, "Admin");

        // Si no es admin y está intentando modificar otro usuario, denegar
        if (currentUser.Id != id && !isAdmin)
            return Results.Forbid();

        // Actualizar campos básicos (todos los usuarios pueden modificar estos campos de sí mismos)
        userToUpdate.UserName = updateDto.UserName ?? userToUpdate.UserName;
        userToUpdate.Email = updateDto.Email ?? userToUpdate.Email;
        userToUpdate.Nombre = updateDto.Nombre ?? userToUpdate.Nombre;
        userToUpdate.Apellidos = updateDto.Apellidos ?? userToUpdate.Apellidos;
        userToUpdate.PhoneNumber = updateDto.Telefono ?? userToUpdate.PhoneNumber;

        // Solo admin puede modificar estado y roles
        if (isAdmin)
        {
            if (updateDto.Estado.HasValue)
                userToUpdate.Estado = updateDto.Estado.Value;

            if (updateDto.Roles != null)
            {
                var currentRoles = await userManager.GetRolesAsync(userToUpdate);
                await userManager.RemoveFromRolesAsync(userToUpdate, currentRoles);
                await userManager.AddToRolesAsync(userToUpdate, updateDto.Roles);
            }
        }
        // Manejo de cambio de contraseña
        if (!string.IsNullOrEmpty(updateDto.CurrentPassword) && !string.IsNullOrEmpty(updateDto.NewPassword))
        {
            // Solo el propio usuario puede cambiar su contraseña (el admin no puede cambiarla directamente)
            if (currentUser.Id != id)
                return Results.Forbid();

            // Verificar la contraseña actual
            var passwordCheck = await signInManager.CheckPasswordSignInAsync(userToUpdate, updateDto.CurrentPassword, false);
            if (!passwordCheck.Succeeded)
                return Results.BadRequest("La contraseña actual es incorrecta");

            // Cambiar la contraseña
            var token = await userManager.GeneratePasswordResetTokenAsync(userToUpdate);
            var resultPassword = await userManager.ResetPasswordAsync(userToUpdate, token, updateDto.NewPassword);
            if (!resultPassword.Succeeded)
                return Results.BadRequest(resultPassword.Errors);
        }

        var result = await userManager.UpdateAsync(userToUpdate);
        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        return Results.Ok();
    })
      .WithName("ActualizarUsuario")
      .WithOpenApi();

    
   
}
//CONSULTAS
void ConfigureConsultaEndpoints(RouteGroupBuilder group)
{
    // Endpoints de consulta - PROBADO
    group.MapGet("/roles/{id:int}", async (
        [FromRoute] int id,
        [FromServices] RoleManager<Rol> roleManager) =>
    {
        var rol = await roleManager.FindByIdAsync(id.ToString());
        return rol == null ? Results.NotFound() : Results.Ok(rol);
    }).WithName("ObtenerRolPorId").WithOpenApi();

    // Obtener lista de todos los roles - PROBADO
    group.MapGet("/roles/", async (
        [FromServices] RoleManager<Rol> roleManager) =>
    {
        var roles = roleManager.Roles.ToList();

        return Results.Ok(roles.Select(r => new
        {
            r.Id,
            r.Name,
            r.NormalizedName
            // Agrega más propiedades si es necesario
        }));
    }).WithName("Roles").WithOpenApi();

    group.MapGet("/admin/usuarios",
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")] async (
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] ILogger<Program> logger,
        [FromQuery] int pagina = 1,
        [FromQuery] int tamanoPagina = 10,
        [FromQuery] string filtro = "",
        [FromQuery] string sortOrder = "") =>
    {
       
        // Validación de parámetros
        if (pagina < 1) pagina = 1;
        if (tamanoPagina < 1 || tamanoPagina > 100) tamanoPagina = 10;

        try
        {
            var query = userManager.Users.AsQueryable();

            // Aplicar filtro si existe
            if (!string.IsNullOrEmpty(filtro))
            {
                filtro = filtro.ToLower();
                query = query.Where(u =>
                    u.UserName.ToLower().Contains(filtro) ||
                    u.Email.ToLower().Contains(filtro) ||
                    (u.Nombre + " " + u.Apellidos).ToLower().Contains(filtro));
            }

            // Aplicar ordenación
            query = sortOrder switch
            {
                "name_asc" => query.OrderBy(u => u.UserName),
                "name_desc" => query.OrderByDescending(u => u.UserName),
                "fullname_asc" => query.OrderBy(u => u.Nombre + " " + u.Apellidos),
                "fullname_desc" => query.OrderByDescending(u => u.Nombre + " " + u.Apellidos),
                "email_asc" => query.OrderBy(u => u.Email),
                "email_desc" => query.OrderByDescending(u => u.Email),
                "date_asc" => query.OrderBy(u => u.FechaCreacion),
                "date_desc" => query.OrderByDescending(u => u.FechaCreacion),
                _ => query.OrderBy(u => u.UserName) // Orden por defecto
            };

            var totalUsuarios = await query.CountAsync();

            // Paginación y selección de campos
            var usuarios = await query
                .Skip((pagina - 1) * tamanoPagina)
                .Take(tamanoPagina)
                .Select(u => new
                {
                    u.Id,
                    u.UserName,
                    u.Email,
                    NombreCompleto = $"{u.Nombre} {u.Apellidos}",
                    u.FechaCreacion,
                    u.Estado,
                    u.UltimoAcceso,
                    u.FechaCaducidadContrasena
                })
                .ToListAsync();

            // Obtener roles para cada usuario
            var usuariosDTO = new List<ListaUsuariosDTO>();
            foreach (var u in usuarios)
            {
                var userEntity = await userManager.FindByIdAsync(u.Id.ToString());
                var roles = await userManager.GetRolesAsync(userEntity);

                usuariosDTO.Add(new ListaUsuariosDTO
                {
                    Id = u.Id,
                    UserName = u.UserName,
                    Email = u.Email,
                    NombreCompleto = u.NombreCompleto,
                    FechaCreacion = u.FechaCreacion,
                    UltimoAcceso = u.UltimoAcceso,
                    FechaCaducidadContrasena = u.FechaCaducidadContrasena,
                    Estado = u.Estado,
                    Roles = roles.ToList()
                });
            }

            // Preparar respuesta
            var resultado = new PaginacionResponse<ListaUsuariosDTO>
            {
                Pagina = pagina,
                TamanoPagina = tamanoPagina,
                Total = totalUsuarios,
                Datos = usuariosDTO
            };

            return Results.Ok(resultado);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al obtener lista de usuarios");
            return Results.Problem("Error interno al obtener usuarios");
        }
    }).WithName("ListaUsuarios").WithOpenApi();

}
//MODIFICACIONES
void ConfigureModificacionEndpoints(RouteGroupBuilder group)
{
    
}

//TALLERES
void ConfigureTalleresEndpoints(RouteGroupBuilder group)
{
    //PROBADO
    group.MapPost("/crear", async (
         TallerDTO tallerdto,
         MyIdentityDbContext context,
         ILogger<Program> logger) =>
        {
            try
            {
                // Crear el taller
                var taller = new Taller
                {
                    Nombre = tallerdto.Nombre,
                    Descripcion = tallerdto.Descripcion,
                    Objetivos = tallerdto.Objetivos,
                    Estado = true,
                    FechaActualizacion = DateTime.UtcNow,
                    FechaCreacion = DateTime.UtcNow
                };

                context.Talleres.Add(taller);
                await context.SaveChangesAsync();

                logger.LogInformation("Taller creado con éxito: {Nombre} (ID: {Id})", taller.Nombre, taller.Id);

                return Results.Ok(new
                {
                    success = true,
                    message = $"Taller '{taller.Nombre}' registrado exitosamente",
                    data = new
                    {
                        Taller = new
                        {
                            Id = taller.Id,
                            Nombre = taller.Nombre,
                            Descripcion = taller.Descripcion,
                            Objetivos = taller.Objetivos,
                            Estado = taller.Estado,
                            FechaCreacion = taller.FechaCreacion,
                            FechaActualizacion = taller.FechaActualizacion
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error al crear el taller");
                return Results.Json(new
                {
                    success = false,
                    message = "Error interno del servidor",
                    error = ex.Message
                }, statusCode: 500);
            }
        })
     .WithName("CrearTaller")
     .WithOpenApi();
    //PROBADO
    group.MapGet("/listar", async (MyIdentityDbContext dbContext) =>
    {
        try
        {
            var talleres = await dbContext.Talleres
                .Select(t => new ListaTalleresDTO
                {
                    Id = t.Id,
                    Nombre = t.Nombre,
                    Descripcion = t.Descripcion,
                    Objetivos = t.Objetivos,
                    Estado = t.Estado,
                    FechaCreacion = t.FechaCreacion,
                    FechaActualizacion = t.FechaActualizacion
                })
                .ToListAsync();

            return Results.Ok(talleres);
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error al obtener los talleres: {ex.Message}");
        }
    })
    .WithName("ListarTalleres")
    .WithOpenApi();
    //PROBADO
    group.MapPut("/editar/{id}", async (
        int id,
        TallerDTO tallerdto,
        MyIdentityDbContext context,
        ILogger<Program> logger) =>
    {
        try
        {
            // Buscar el taller existente
            var tallerExistente = await context.Talleres.FindAsync(id);

            if (tallerExistente == null)
            {
                logger.LogWarning("No se encontró el taller con ID: {Id}", id);
                return Results.NotFound(new
                {
                    success = false,
                    message = $"No se encontró el taller con ID {id}"
                });
            }

            // Actualizar los campos del taller
            if (tallerdto.Nombre != null)
            {
                tallerExistente.Nombre = tallerdto.Nombre;
            }

            if (tallerdto.Descripcion != null)
            {
                tallerExistente.Descripcion = tallerdto.Descripcion;
            }

            if (tallerdto.Objetivos != null)
            {
                tallerExistente.Objetivos = tallerdto.Objetivos;
            }

            tallerExistente.FechaActualizacion = DateTime.UtcNow;

            await context.SaveChangesAsync();

            logger.LogInformation("Taller actualizado con éxito: {Nombre} (ID: {Id})",
                tallerExistente.Nombre, tallerExistente.Id);

            return Results.Ok(new
            {
                success = true,
                message = $"Taller '{tallerExistente.Nombre}' actualizado exitosamente",
                data = new
                {
                    Taller = new
                    {
                        Id = tallerExistente.Id,
                        Nombre = tallerExistente.Nombre,
                        Descripcion = tallerExistente.Descripcion,
                        Objetivos = tallerExistente.Objetivos,
                        Estado = tallerExistente.Estado,
                        FechaCreacion = tallerExistente.FechaCreacion,
                        FechaActualizacion = tallerExistente.FechaActualizacion
                    }
                }
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al actualizar el taller con ID: {Id}", id);
            return Results.Json(new
            {
                success = false,
                message = "Error interno del servidor al actualizar el taller",
                error = ex.Message
            }, statusCode: 500);
        }
    })
    .WithName("EditarTaller")
    .WithOpenApi();
    //PROBADO
    group.MapDelete("/desabilitar/{id}", async (
        int id,
        MyIdentityDbContext context,
        ILogger<Program> logger) =>
    {
        try
        {
            // Buscar el taller existente
            var tallerExistente = await context.Talleres.FindAsync(id);

            if (tallerExistente == null)
            {
                logger.LogWarning("No se encontró el taller con ID: {Id}", id);
                return Results.NotFound(new
                {
                    success = false,
                    message = $"No se encontró el taller con ID {id}"
                });
            }

            // Realizar borrado lógico (cambiar estado a false)
            tallerExistente.Estado = false;
            tallerExistente.FechaActualizacion = DateTime.UtcNow;

            await context.SaveChangesAsync();

            logger.LogInformation("Taller desactivado con éxito: {Nombre} (ID: {Id})",
                tallerExistente.Nombre, tallerExistente.Id);

            return Results.Ok(new
            {
                success = true,
                message = $"Taller '{tallerExistente.Nombre}' desactivado exitosamente",
                data = new
                {
                    Id = tallerExistente.Id,
                    Nombre = tallerExistente.Nombre,
                    Estado = tallerExistente.Estado
                }
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al desactivar el taller con ID: {Id}", id);
            return Results.Json(new
            {
                success = false,
                message = "Error interno del servidor al desactivar el taller",
                error = ex.Message
            }, statusCode: 500);
        }
    })
    .WithName("DesabilitarTaller")
    .WithOpenApi();
    //PROBADO
    group.MapDelete("/eliminar-fisico/{id}", async (
        int id,
        MyIdentityDbContext context,
        ILogger<Program> logger) =>
    {
        try
        {
            // Buscar el taller existente
            var tallerExistente = await context.Talleres.FindAsync(id);

            if (tallerExistente == null)
            {
                logger.LogWarning("No se encontró el taller con ID: {Id}", id);
                return Results.NotFound(new
                {
                    success = false,
                    message = $"No se encontró el taller con ID {id}"
                });
            }

            // Eliminación física
            context.Talleres.Remove(tallerExistente);
            await context.SaveChangesAsync();

            logger.LogInformation("Taller eliminado permanentemente: {Nombre} (ID: {Id})",
                tallerExistente.Nombre, id);

            return Results.Ok(new
            {
                success = true,
                message = $"Taller '{tallerExistente.Nombre}' eliminado permanentemente",
                data = new
                {
                    Id = id,
                    Nombre = tallerExistente.Nombre
                }
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al eliminar el taller con ID: {Id}", id);
            return Results.Json(new
            {
                success = false,
                message = "Error interno del servidor al eliminar el taller",
                error = ex.Message
            }, statusCode: 500);
        }
    })
    .WithName("EliminarTallerFisico")
    .WithOpenApi();


}

//app.UseSwagger();
//app.UseSwaggerUI(c =>
//{
//    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AccionSocial API V1");
//});

    //app.UseHttpsRedirection();


public class ErrorResponse
{
    public string Message { get; set; }
    public IEnumerable<string> Errors { get; set; }
}

