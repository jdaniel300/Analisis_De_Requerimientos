using AccionSocial.web.Services.Admin;
using AccionSocial.web.Services.Auth;
using AccionSocial.web.Services.Token;
using AccionSocial.web.Services.Usr;
using AccionSocial.web.Services.Usuario;
using Jose;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Tokens;
using Polly;
using Polly.Extensions.Http;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
{
    return Policy<HttpResponseMessage>
        .Handle<HttpRequestException>()
        .OrResult(r => (int)r.StatusCode >= 500)
        .WaitAndRetryAsync(2, retryAttempt => TimeSpan.FromSeconds(1));
}

static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy()
{
    return Policy<HttpResponseMessage>
        .Handle<HttpRequestException>()
        .OrResult(r => (int)r.StatusCode >= 500)
        .CircuitBreakerAsync(3, TimeSpan.FromSeconds(10));
}

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Lax;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;

    // Opcional: configuración para consentimiento de cookies
    options.CheckConsentNeeded = context => false; // O true si manejas consentimiento
    options.ConsentCookieValue = "true";
});

builder.Services.AddHttpContextAccessor();
builder.Services.AddLogging();
builder.Services.AddMemoryCache();
// Configuración de Kestrel
builder.WebHost.ConfigureKestrel(serverOptions => {
    serverOptions.ListenAnyIP(8080);

});



builder.Services.AddScoped<IAdministradorService, AdministradorService>();
builder.Services.AddScoped<ITokenRefreshService, TokenRefreshService>();
builder.Services.AddScoped<ITokenStorageService, BrowserTokenStorage>();
builder.Services.AddTransient<AuthTokenHandler>();
builder.Services.AddScoped<IUsuarioService, UsuarioService>();

builder.Services.AddHttpClient<IUsuarioService, UsuarioService>(client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]
        ?? throw new InvalidOperationException("Missing ApiSettings:BaseUrl"));
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
});

builder.Services.AddHttpClient("AccionSocialApi", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]
        ?? throw new InvalidOperationException("Missing ApiSettings:BaseUrl"));

    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(
        new MediaTypeWithQualityHeaderValue("application/json"));

    // Opcional: Headers comunes para todas las requests
    client.DefaultRequestHeaders.Add("X-Application-Name", "AccionSocial.Web");
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    // Deshabilitar manejo automático de redirecciones/autenticación
    AllowAutoRedirect = false,
    AutomaticDecompression = DecompressionMethods.None,
    UseCookies = false
})
.AddHttpMessageHandler<AuthTokenHandler>()
.AddPolicyHandler(GetRetryPolicy())        
.AddPolicyHandler(GetCircuitBreakerPolicy());

builder.Services.AddHttpClient("AuthApi", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]);
    // Configuración específica...
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = false,
    UseCookies = false
})
.AddHttpMessageHandler<AuthTokenHandler>();

builder.Services.AddHttpClient<ITokenRefreshService, TokenRefreshService>(client =>
{
    var baseUrl = builder.Configuration["ApiSettings:BaseUrl"]
        ?? throw new InvalidOperationException("Missing ApiSettings:BaseUrl");
    client.BaseAddress = new Uri(baseUrl);

    // Configuración específica para refresh tokens
    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(
        new MediaTypeWithQualityHeaderValue("application/json"));
});


builder.Services.AddScoped<IAuthService>(provider =>
{
    var httpClient = provider.GetRequiredService<IHttpClientFactory>()
                          .CreateClient("AccionSocialApi");
    var tokenService = provider.GetRequiredService<ITokenStorageService>();
    var logger = provider.GetRequiredService<ILogger<AuthService>>();
    var cache = provider.GetRequiredService<IMemoryCache>();

    return new AuthService(httpClient, tokenService, logger, cache);
});



builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Login/Login";
    options.AccessDeniedPath = "/Login/AccessDenied";
    options.Cookie.SameSite = SameSiteMode.Lax; // Cambiado de Strict a Lax para mejor compatibilidad
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ExpireTimeSpan = TimeSpan.FromHours(1); // Aumentado a 1 hora
    options.SlidingExpiration = true;
    options.Cookie.Name = "AccionSocial.Auth"; // Usa un nombre específico de tu app
    options.Cookie.HttpOnly = true;
    options.Cookie.Domain = builder.Configuration["CookieDomain"]; // Opcional: si necesitas dominio específico
    options.Cookie.Path = "/"; // Asegúrate que esté en root
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
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("SecurePolicy", builder =>
    {
        builder.WithOrigins(
                "http://localhost:8080",
                "http://localhost:8090",
                "http://accionsocial.web:8080"
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials() 
            .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
    });
});

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Lax;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "XSRF-TOKEN";
    options.Cookie.HttpOnly = false;
    options.HeaderName = "X-XSRF-TOKEN";

    if (builder.Environment.IsDevelopment())
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    }
    else
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    }
});

var keysDirectory = builder.Configuration["DataProtection:KeysDirectory"] ?? "/app/keys";
var applicationName = builder.Configuration["DataProtection:ApplicationName"] ?? "AccionSocial";

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysDirectory))
    .SetApplicationName(applicationName)
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

//builder.Services.AddHttpsRedirection(options => {
//    options.HttpsPort = 8443;
//});

var app = builder.Build();



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts(); // Solo en producción
    // app.UseHttpsRedirection(); // Descomentar en producción
}

//app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseCors("AllowedOrigins");

app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();

var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
if (!Directory.Exists(uploadsPath))
{
    Directory.CreateDirectory(uploadsPath);
}

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(uploadsPath), 
    RequestPath = "/uploads"
});

app.Use(async (context, next) =>
{
    await next();

    // Redirección para endpoints no autenticados (opcional)
    if (context.Response.StatusCode == 401 && !context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.Redirect($"/Login/Login?returnUrl={Uri.EscapeDataString(context.Request.Path)}");
    }
});

app.MapControllers();



app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");



app.Run();
