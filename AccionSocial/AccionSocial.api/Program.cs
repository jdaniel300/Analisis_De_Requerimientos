using AccionSocialModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

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
builder.Services.AddSwaggerGen();

var app = builder.Build();

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

if (!app.Environment.IsDevelopment())
{
    app.UseForwardedHeaders();
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
