using AccionSocialModels;
using AccionSocialModels.DTO;
using AccionSocialModels.Response;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
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

builder.Services.AddHttpContextAccessor();

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

            // Crear roles
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new Rol { Name = "Admin" });
                logger.LogInformation("Rol 'Admin' creado.");
            }
            if (!await roleManager.RoleExistsAsync("Straff"))
            {
                await roleManager.CreateAsync(new Rol { Name = "Straff" });
                logger.LogInformation("Rol 'Staff' creado.");
            }
            if (!await roleManager.RoleExistsAsync("Participante"))
            {
                await roleManager.CreateAsync(new Rol { Name = "Participante" });
                logger.LogInformation("Rol 'Participante' creado.");
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



// AUTH
var authGroup = app.MapGroup("/api/auth").WithTags("Authentication");
//CONSULTAS TABLAS
var consGropu = app.MapGroup("/api/consultas").WithTags("Consultas");
//MODIFICACION
var modGroup = app.MapGroup("/api/mod").WithTags("Modificaciones");


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


//------------------AUTENTICACION-------------------->
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
authGroup.MapGet("/usuarioActual", async (
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
})
.WithName("UsuarioActual")
.WithOpenApi();

// Eliminar usuario por ID (solo para usuarios con rol Admin)
authGroup.MapDelete("/eliminar/{id}", async (
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
})
.RequireAuthorization(policy => policy.RequireRole("Admin"))
.WithName("eliminarUsuarioPorIdAdmin")
.WithOpenApi();

// Eliminar el usuario actual (auto-eliminación)
authGroup.MapDelete("/usuarioActual", async (
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
authGroup.MapPost("/register", async (
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
authGroup.MapPost("/admin/register", async (
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

//OPTENER ROLES
consGropu.MapGet("/roles/{id:int}", async (
    [FromRoute] int id,
    [FromServices] RoleManager<Rol> roleManager) =>
{
    var rol = await roleManager.FindByIdAsync(id.ToString());

    if (rol == null)
    {
        return Results.NotFound($"No se encontró un rol con el ID {id}");
    }

    return Results.Ok(rol);
})
.WithName("ObtenerRolPorUd")
.WithOpenApi()
.Produces<Rol>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status404NotFound);

// Obtener lista de todos los roles
consGropu.MapGet("/consulta/roles/", async (
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


// OBTENER LISTA DE USUARIOS (SOLO ADMIN)
consGropu.MapGet("/admin/usuarios", async (
    [FromServices] UserManager<Usuario> userManager,
    [FromServices] RoleManager<Rol> roleManager,
    [FromServices] IHttpContextAccessor httpContextAccessor,
    [FromServices] ILogger<Program> logger,
    [FromQuery] int pagina = 1,
    [FromQuery] int tamanoPagina = 10,
    [FromQuery] string filtro = "") =>
{
    // Verificar si el usuario actual es admin
    var usuarioActual = await userManager.GetUserAsync(httpContextAccessor.HttpContext.User);
    if (usuarioActual == null || !(await userManager.IsInRoleAsync(usuarioActual, "Admin")))
    {
        return Results.Unauthorized();
    }

    try
    {
        var query = userManager.Users.AsQueryable();

        if (!string.IsNullOrEmpty(filtro))
        {
            query = query.Where(u =>
                u.UserName.Contains(filtro) ||
                u.Email.Contains(filtro) ||
                $"{u.Nombre} {u.Apellidos}".Contains(filtro));
        }

        var totalUsuarios = await query.CountAsync();
        var usuarios = await query
            .OrderBy(u => u.UserName)
            .Skip((pagina - 1) * tamanoPagina)
            .Take(tamanoPagina)
            .Select(u => new ListaUsuariosDTO
            {
                Id = u.Id,
                UserName = u.UserName,
                Email = u.Email,
                NombreCompleto = $"{u.Nombre} {u.Apellidos}",
                FechaCreacion = u.FechaCreacion,
                Estado = u.Estado
            })
            .ToListAsync();

        // Obtener roles para cada usuario (versión corregida)
        foreach (var usuario in usuarios)
        {
            var userEntity = await userManager.FindByIdAsync(usuario.Id.ToString());
            var roles = await userManager.GetRolesAsync(userEntity);
            usuario.Roles = roles.ToList();
        }

        var resultado = new PaginacionResponse<ListaUsuariosDTO>
        {
            Pagina = pagina,
            TamanoPagina = tamanoPagina,
            Total = totalUsuarios,
            Datos = usuarios
        };

        return Results.Ok(resultado);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error al obtener lista de usuarios");
        return Results.Problem("Error interno al obtener usuarios");
    }
});

modGroup.MapPut("/admin/usuarios/{id}", async (
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


// Obtener datos de cualquier usuario por ID (solo para administradores)
authGroup.MapGet("/admin/usuarios/{id}", async (
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

// ACTUALIZAR USUARIO ACTUAL Y/O CONTRASEÑA
modGroup.MapPut("/usr/", async (
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






app.Run();


public class ErrorResponse
{
    public string Message { get; set; }
    public IEnumerable<string> Errors { get; set; }
}

