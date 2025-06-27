
using AccionSocial.api.Services.Token;
using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
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

/* ==================== INICIALIZACIÓN DE LA BASE DE DATOS ==================== */
await InitializeDatabase(app);


/* ==================== ENDPOINTS ==================== */
var authGroup = app.MapGroup("/api/auth").WithTags("Autenticacion");
var consGroup = app.MapGroup("/api/consultas").WithTags("Consultas");
var modGroup = app.MapGroup("/api/mod").WithTags("Modificaciones");


ConfigureAuthEndpoints(authGroup);
ConfigureConsultaEndpoints(consGroup);
ConfigureModificacionEndpoints(modGroup);

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

    // Crear usuario admin
    var adminUser = await userManager.FindByNameAsync("admin") ?? new Usuario
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

    if (adminUser.Id == null)
    {
        var createResult = await userManager.CreateAsync(adminUser, "AdminAccion123!");
        if (!createResult.Succeeded)
        {
            logger.LogError("Failed to create admin user: {Errors}",
                string.Join(", ", createResult.Errors.Select(e => e.Description)));
            return;
        }
    }

    if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
    {
        var addRoleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
        if (!addRoleResult.Succeeded)
        {
            logger.LogError("Failed to add Admin role: {Errors}",
                string.Join(", ", addRoleResult.Errors.Select(e => e.Description)));
        }
    }
}

void ConfigureAuthEndpoints(RouteGroupBuilder group)
{
    // Login
    group.MapPost("/login", async (
        [FromBody] LoginDTO request,
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] SignInManager<Usuario> signInManager,
        [FromServices] ITokenService tokenService,
        [FromServices] ILogger<Program> logger) =>
    {
        var user = await userManager.FindByEmailAsync(request.UsernameOrEmail) ??
                   await userManager.FindByNameAsync(request.UsernameOrEmail);

        if (user == null || !user.Estado)
            return Results.Unauthorized();

        var result = await signInManager.PasswordSignInAsync(
            user.UserName, request.Password, request.RememberMe, lockoutOnFailure: true);

        if (!result.Succeeded)
            return Results.Unauthorized();

        var roles = await userManager.GetRolesAsync(user);
        var token = tokenService.GenerateJwtToken(user, roles);

        return Results.Ok(new
        {
            Token = token,
            User = new
            {
                user.UserName,
                user.Email,
                NombreCompleto = $"{user.Nombre} {user.Apellidos}",
                Roles = roles
            }
        });
    }).WithName("Login").WithOpenApi();

    group.MapPost("/refresh-token", async (
    [FromBody] RefreshTokenRequest request,
    [FromServices] ITokenService tokenService,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] ILogger<Program> logger,
    [FromServices] IOptions<JwtSettings> jwtSettings) =>
    {
        // Validar que el token no esté invalidado
        if (await tokenService.IsTokenInvalidatedAsync(request.Token))
            return Results.Unauthorized();

        // Validar el token principal
        var principal = tokenService.GetPrincipalFromToken(request.Token);
        if (principal == null)
            return Results.Unauthorized();

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return Results.Unauthorized();

        var user = await userManager.FindByIdAsync(userId);
        if (user == null || user.RefreshToken != request.RefreshToken ||
            user.RefreshTokenExpiry <= DateTime.UtcNow)
            return Results.Unauthorized();

        // Generar nuevo token
        var roles = await userManager.GetRolesAsync(user);
        var newToken = tokenService.GenerateJwtToken(user, roles);

        // Opcional: generar nuevo refresh token
        var newRefreshToken = tokenService.GenerateRefreshToken();
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(jwtSettings.Value.RefreshTokenExpireDays);
        await userManager.UpdateAsync(user);

        return Results.Ok(new
        {
            Token = newToken,
            RefreshToken = newRefreshToken
        });
    }).WithName("RefreshToken").WithOpenApi();

    // Logout
    group.MapPost("/logout", async (
    [FromServices] ITokenService tokenService,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] ILogger<Program> logger,
    HttpContext httpContext) =>
    {
        try
        {
            var token = httpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            // Invalidar el token
            await tokenService.InvalidateTokenAsync(token);

            // Opcional: limpiar refresh token del usuario
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.RefreshToken = null;
                    await userManager.UpdateAsync(user);
                }
            }

            logger.LogInformation("Token invalidado en el servidor");
            return Results.Ok(new { message = "Sesión cerrada correctamente" });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error durante el logout");
            return Results.Problem("Ocurrió un error al cerrar la sesión");
        }
    }).WithName("Logout").WithOpenApi();

    group.MapGet("/usuarioActual", async (
    ClaimsPrincipal userClaim,
    [FromServices] UserManager<Usuario> userManager) =>
    {
        var user = await userManager.GetUserAsync(userClaim);
        if (user == null)
        {
            return Results.Unauthorized();
        }

        var roles = await userManager.GetRolesAsync(user);

        return Results.Ok(new
        {
            Id = user.Id,
            Username = user.UserName,
            Email = user.Email,
            NombreCompleto = $"{user.Nombre} {user.Apellidos}",
            Roles = roles
        });
    }).WithName("UsuarioActual")
      .WithOpenApi();

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
      .WithName("eliminarUsuarioPorIdAdmin")
      .WithOpenApi();

    group.MapDelete("/usuarioActual", async (
    ClaimsPrincipal userClaim,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] SignInManager<Usuario> signInManager) =>
    {
        var currentUser = await userManager.GetUserAsync(userClaim);
        if (currentUser == null)
        {
            return Results.Unauthorized();
        }

        var result = await userManager.DeleteAsync(currentUser);

        if (!result.Succeeded)
        {
            return Results.Problem(
                detail: string.Join(", ", result.Errors.Select(e => e.Description)),
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Cerrar sesión después de eliminar la cuenta
        await signInManager.SignOutAsync();

        return Results.NoContent();
    });

    //REGISTRO POR LOGIN
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
    })
    .WithName("RegisterUser")
    .WithOpenApi()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest);

    // REGISTRO POR ADMINISTRADOR
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
            return Results.Unauthorized();
        }

        // Validaciones básicas (igual que en el registro normal)
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
                Message = $"Usuario registrado exitosamente con rol {roleName}"
            });
        }
        else
        {
            var errors = result.Errors.Select(e => e.Description);
            logger.LogError("Error al registrar usuario: {Errors}", string.Join(", ", errors));
            return Results.BadRequest(new { Errors = errors });
        }
    })
    .WithName("RegisterUserByAdmin")
    .WithOpenApi()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized);

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
    })
    .WithName("UsuarioPorId")
    .WithOpenApi();
    // [Resto de endpoints de autenticación...]
    // (Mantener la misma estructura para los demás endpoints)
}

void ConfigureConsultaEndpoints(RouteGroupBuilder group)
{
    // Endpoints de consulta
    group.MapGet("/roles/{id:int}", async (
        [FromRoute] int id,
        [FromServices] RoleManager<Rol> roleManager) =>
    {
        var rol = await roleManager.FindByIdAsync(id.ToString());
        return rol == null ? Results.NotFound() : Results.Ok(rol);
    }).WithName("ObtenerRolPorId").WithOpenApi();

    // Obtener lista de todos los roles
    group.MapGet("/consulta/roles/", async (
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
    })
    .WithName("Roles")
    .WithOpenApi(operation => new(operation)
    {
        Summary = "Obtiene todos los roles disponibles",
        Description = "Retorna una lista completa de todos los roles registrados en el sistema."
    })
    .Produces(StatusCodes.Status200OK, typeof(IEnumerable<Rol>), "application/json");

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
    });

}

void ConfigureModificacionEndpoints(RouteGroupBuilder group)
{

    group.MapPut("/admin/usuarios/{id}", async (
    [FromRoute] string id,
    [FromBody] ActualizarRolEstadoDTO actualizarDto,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] RoleManager<Rol> roleManager,
    [FromServices] IHttpContextAccessor httpContextAccessor,
    [FromServices] ILogger<Program> logger) =>
    {
        // 1. VERIFICAR PERMISOS
        var usuarioActual = await userManager.GetUserAsync(httpContextAccessor.HttpContext.User);
        if (usuarioActual == null || !(await userManager.IsInRoleAsync(usuarioActual, "Admin")))
        {
            return Results.Unauthorized();
        }

        // 2. BUSCAR USUARIO
        var usuario = await userManager.FindByIdAsync(id);
        if (usuario == null)
        {
            return Results.NotFound("Usuario no encontrado");
        }

        // 3. VALIDAR AUTO-MODIFICACIÓN
        if (usuarioActual.Id == usuario.Id)
        {
            return Results.BadRequest("No puedes modificarte a ti mismo");
        }

        try
        {
            bool cambiosRealizados = false;
            var cambios = new List<string>();

            // 4. ACTUALIZAR ROL (si se especificó)
            if (!string.IsNullOrEmpty(actualizarDto.NuevoRol))
            {
                if (!await roleManager.RoleExistsAsync(actualizarDto.NuevoRol))
                {
                    return Results.BadRequest($"El rol {actualizarDto.NuevoRol} no existe");
                }

                var rolesActuales = await userManager.GetRolesAsync(usuario);
                await userManager.RemoveFromRolesAsync(usuario, rolesActuales);
                await userManager.AddToRoleAsync(usuario, actualizarDto.NuevoRol);

                cambios.Add($"Rol actualizado a {actualizarDto.NuevoRol}");
                cambiosRealizados = true;
            }

            // 5. ACTUALIZAR ESTADO (si se especificó) - ahora como booleano simple
            if (actualizarDto.Activo.HasValue)
            {
                // Asumiendo que tu entidad Usuario tiene una propiedad booleana Activo
                usuario.Estado = actualizarDto.Activo.Value;
                cambios.Add($"Estado actualizado a {(usuario.Estado ? "Activo" : "Inactivo")}");
                cambiosRealizados = true;
            }

            // 6. GUARDAR CAMBIOS
            if (cambiosRealizados)
            {
                var resultado = await userManager.UpdateAsync(usuario);
                if (!resultado.Succeeded)
                {
                    logger.LogError("Error al actualizar usuario: {Errors}", string.Join(", ", resultado.Errors));
                    return Results.Problem("Error al guardar los cambios");
                }

                logger.LogInformation("Admin {Admin} modificó usuario {UserId}: {Cambios}",
                    usuarioActual.UserName, id, string.Join(", ", cambios));

                return Results.Ok(new
                {
                    Success = true,
                    Message = "Cambios aplicados correctamente",
                    Cambios = cambios,
                    UsuarioId = id
                });
            }

            return Results.BadRequest("No se especificaron cambios válidos");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al actualizar usuario {UserId}", id);
            return Results.Problem("Error interno al procesar la solicitud");
        }
    })
        .WithName("ActualizarUsuario")
        .WithOpenApi(operation => new(operation)
        {
            Summary = "Actualiza rol y/o estado de un usuario",
            Description = "Requiere rol de Administrador. Permite actualizar rol, estado (como booleano) o ambos."
        })
        .Produces<ApiResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status500InternalServerError);


    group.MapPut("/usr/", async (
        [FromBody] ActualizarUsuarioDTO updateDto,
        ClaimsPrincipal userClaim,
        [FromServices] UserManager<Usuario> userManager,
        [FromServices] ILogger<Program> logger) =>
    {
        var user = await userManager.GetUserAsync(userClaim);
        if (user == null)
        {
            return Results.Unauthorized();
        }

        try
        {
            // Actualizar datos básicos
            if (!string.IsNullOrEmpty(updateDto.Nombre))
            {
                user.Nombre = updateDto.Nombre;
            }

            if (!string.IsNullOrEmpty(updateDto.Apellidos))
            {
                user.Apellidos = updateDto.Apellidos;
            }

            if (!string.IsNullOrEmpty(updateDto.PhoneNumber))
            {
                user.PhoneNumber = updateDto.PhoneNumber;
            }

            // Actualizar contraseña si se proporciona
            if (!string.IsNullOrEmpty(updateDto.CurrentPassword) &&
                !string.IsNullOrEmpty(updateDto.NewPassword))
            {
                var changePasswordResult = await userManager.ChangePasswordAsync(
                    user,
                    updateDto.CurrentPassword,
                    updateDto.NewPassword);

                if (!changePasswordResult.Succeeded)
                {
                    logger.LogWarning("Error al cambiar contraseña para usuario {UserId}: {Errors}",
                        user.Id, string.Join(", ", changePasswordResult.Errors.Select(e => e.Description)));

                    return Results.BadRequest(new
                    {
                        Errors = changePasswordResult.Errors.Select(e => e.Description)
                    });
                }

                logger.LogInformation("Usuario {UserId} cambió su contraseña", user.Id);
            }

            // Guardar cambios en el usuario
            var updateResult = await userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                logger.LogWarning("Error al actualizar usuario {UserId}: {Errors}",
                    user.Id, string.Join(", ", updateResult.Errors.Select(e => e.Description)));

                return Results.BadRequest(new
                {
                    Errors = updateResult.Errors.Select(e => e.Description)
                });
            }

            logger.LogInformation("Usuario {UserId} actualizó su perfil", user.Id);

            // Obtener datos actualizados
            var roles = await userManager.GetRolesAsync(user);

            return Results.Ok(new
            {
                Message = "Perfil actualizado correctamente",
                Username = user.UserName,
                Email = user.Email,
                NombreCompleto = $"{user.Nombre} {user.Apellidos}",
                PhoneNumber = user.PhoneNumber,
                Roles = roles
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error al actualizar usuario {UserId}", user.Id);
            return Results.Problem("Error interno al actualizar el perfil");
        }
    })
    .RequireAuthorization()
    .WithName("ActualizarUsuarioActual")
    .WithOpenApi()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status500InternalServerError);
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

