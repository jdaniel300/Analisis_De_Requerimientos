using AccionSocialModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configuración de DbContext con Identity
var conn = builder.Configuration.GetConnectionString("Database");
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
    serverOptions.ListenAnyIP(8080);
    //serverOptions.ListenAnyIP(8443, listenOptions => {
    //    listenOptions.UseHttps("certificate.pfx", "password");
    //});
});

// Añadir compresión de respuesta
builder.Services.AddResponseCompression(options => {
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});

var app = builder.Build();


// Aplicar migraciones automáticamente y crear usuario admin
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
            logger.LogInformation("Applying migrations... Attempt {AttemptNumber}", i + 1);

            // Aplicar migraciones primero
            var dbContext = services.GetRequiredService<MyIdentityDbContext>();
            await dbContext.Database.MigrateAsync();

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
                    // Asignar rol Admin al usuario recién creado
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
                // Verificar si el usuario existente ya tiene el rol Admin
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

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
   
    app.UseForwardedHeaders();
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
