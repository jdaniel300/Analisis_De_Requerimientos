using AccionSocialModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

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

// Configuración de DataProtection
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .SetApplicationName("AccionSocial");

// Configuración de Kestrel
builder.WebHost.ConfigureKestrel(serverOptions => {
    serverOptions.Limits.MaxConcurrentConnections = 100;
    serverOptions.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
    serverOptions.ListenAnyIP(8081);
});

// Añadir compresión de respuesta
builder.Services.AddResponseCompression(options => {
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
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

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = false;
});

builder.Services.AddAuthorization(options =>
{
    // Define la política "Admin" que requiere el rol "Admin"
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));

    // Opcional: Otras políticas que necesites
    // options.AddPolicy("OtroRol", policy => policy.RequireRole("OtroRol"));
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowWebApp",
        builder => builder
            .WithOrigins("http://localhost:8090") 
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});


var app = builder.Build();
//CREACION DE BASE DE DATOS 
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<Program>>();
    var maxRetryAttempts = 10;
    var pauseBetweenFailures = TimeSpan.FromSeconds(5);

    for (int i = 0; i < maxRetryAttempts; i++)
    {
        try
        {
            logger.LogInformation("Checking database... Attempt {AttemptNumber}", i + 1);

            var dbContext = services.GetRequiredService<MyIdentityDbContext>();

            // Verificar si la base de datos existe
            if (await dbContext.Database.CanConnectAsync())
            {
                logger.LogInformation("Database already exists. Checking for pending migrations...");

                // Obtener migraciones pendientes
                var pendingMigrations = await dbContext.Database.GetPendingMigrationsAsync();
                if (pendingMigrations.Any())
                {
                    logger.LogInformation("Applying {Count} pending migrations...", pendingMigrations.Count());
                    await dbContext.Database.MigrateAsync();
                }
                else
                {
                    logger.LogInformation("Database is up to date. No migrations to apply.");
                }
            }
            else
            {
                logger.LogInformation("Database does not exist. Creating and applying migrations...");
                await dbContext.Database.MigrateAsync();
            }

            // Resto de tu lógica de inicialización (roles y usuario admin)
            var roleManager = services.GetRequiredService<RoleManager<Rol>>();
            var userManager = services.GetRequiredService<UserManager<Usuario>>();

            // Crear rol "Admin" si no existe
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new Rol { Name = "Admin" });
                logger.LogInformation("Rol 'Admin' creado.");
            }

            // Crear usuario admin si no existe
            var adminUser = await userManager.FindByNameAsync("admin");
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
                var result = await userManager.CreateAsync(adminUser, "AdminAccion123!");

                if (result.Succeeded)
                {
                    var roleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
                    if (roleResult.Succeeded)
                    {
                        logger.LogInformation("Usuario admin creado y rol asignado correctamente.");
                    }
                    else
                    {
                        logger.LogError("Error al asignar rol: {Errors}",
                            string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    logger.LogError("Error al crear admin: {Errors}",
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                var isInRole = await userManager.IsInRoleAsync(adminUser, "Admin");
                if (!isInRole)
                {
                    var roleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
                    if (roleResult.Succeeded)
                    {
                        logger.LogInformation("Rol Admin asignado al usuario admin existente.");
                    }
                    else
                    {
                        logger.LogError("Error al asignar rol al usuario existente: {Errors}",
                            string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                    }
                }
            }

            break; // Si tiene éxito, sal del bucle
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during database initialization. Attempt {AttemptNumber}", i + 1);

            if (i == maxRetryAttempts - 1)
            {
                logger.LogError("Max retry attempts reached. Application will exit.");
                throw;
            }

            await Task.Delay(pauseBetweenFailures);
        }
    }
}

app.UseResponseCompression();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AccionSocial API V1");
});

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("AllowWebApp");
app.UseAuthentication();
app.UseAuthorization();




var authGroup = app.MapGroup("/api/auth").WithTags("Authentication");
//LOGIN
authGroup.MapPost("/login", async (
    [FromBody] LoginDTO request,
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] SignInManager<Usuario> signInManager,
    [FromServices] ILogger<Program> logger) =>
{
    // Buscar usuario por email o nombre de usuario
    var user = await userManager.FindByEmailAsync(request.UsernameOrEmail) ??
               await userManager.FindByNameAsync(request.UsernameOrEmail);

    if (user == null)
    {
        logger.LogWarning("Intento de inicio de sesión fallido: usuario no encontrado");
        return Results.Unauthorized();
    }

    if (!user.Estado)
    {
        logger.LogWarning($"Intento de inicio de sesión fallido: usuario {user.UserName} desactivado");
        return Results.Unauthorized();
    }

    // Verificar contraseña
    var result = await signInManager.PasswordSignInAsync(
        user.UserName,
        request.Password,
        request.RememberMe,
        lockoutOnFailure: false);

    if (result.Succeeded)
    {
        logger.LogInformation($"Usuario {user.UserName} inició sesión correctamente");

        // Actualizar último acceso
        user.UltimoAcceso = DateTime.Now;
        await userManager.UpdateAsync(user);

        // Obtener roles del usuario
        var roles = await userManager.GetRolesAsync(user);

        return Results.Ok(new
        {
            Username = user.UserName,
            Email = user.Email,
            NombreCompleto = $"{user.Nombre} {user.Apellidos}",
            Roles = roles
        });
    }

    logger.LogWarning($"Intento de inicio de sesión fallido para el usuario {user.UserName}");
    return Results.Unauthorized();
})
.WithName("Login")
.WithOpenApi(operation => new(operation)
{
    Summary = "Iniciar sesión",
    Description = "Permite a los usuarios iniciar sesión con su nombre de usuario/email y contraseña"
})
.Produces<LoginResponse>(StatusCodes.Status200OK, "application/json")
.Produces(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status500InternalServerError);

//LOGOUT
authGroup.MapPost("/logout", async (
    [FromServices] SignInManager<Usuario> signInManager,
    [FromServices] ILogger<Program> logger) =>
{
    await signInManager.SignOutAsync();
    logger.LogInformation("Usuario cerró sesión");
    return Results.Ok(new { message = "Sesión cerrada correctamente" });
})
.WithName("Logout")
.WithOpenApi();

// USUARIO ACTUAL
authGroup.MapGet("/current-user", async (
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
        Username = user.UserName,
        Email = user.Email,
        NombreCompleto = $"{user.Nombre} {user.Apellidos}",
        Roles = roles
    });
})
.RequireAuthorization()
.WithName("GetCurrentUser")
.WithOpenApi();

//REGISTRO
app.MapPost("/api/register", async (
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
//PARA PRUEBAS ->
app.MapGet("/api/test", () => "Funciona!");

app.Run();


public class ErrorResponse
{
    public string Message { get; set; }
    public IEnumerable<string> Errors { get; set; }
}

