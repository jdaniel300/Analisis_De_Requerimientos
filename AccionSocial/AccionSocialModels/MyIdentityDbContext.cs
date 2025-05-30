using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;



namespace AccionSocialModels
{
    public class MyIdentityDbContext : IdentityDbContext<Usuario, Rol, int>
    {
        public MyIdentityDbContext(DbContextOptions<MyIdentityDbContext> options)
            : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configuración específica para Usuario
            modelBuilder.Entity<Usuario>(b =>
            {
                b.ToTable("Usuarios");
                // Asegúrate de mapear TODOS los campos de Identity
                b.Property(u => u.Id).HasColumnName("Id");
                b.Property(u => u.UserName).HasMaxLength(256);
                b.Property(u => u.NormalizedUserName).HasMaxLength(256);
                b.Property(u => u.Email).HasMaxLength(256);
                b.Property(u => u.NormalizedEmail).HasMaxLength(256);
                b.Property(u => u.PasswordHash).HasMaxLength(500);
                b.Property(u => u.SecurityStamp).HasMaxLength(500);
                b.Property(u => u.ConcurrencyStamp).HasMaxLength(500);

                // Tus campos personalizados
                b.Property(u => u.Nombre).HasMaxLength(100).IsRequired();
                b.Property(u => u.Apellidos).HasMaxLength(255).IsRequired();
                b.Property(u => u.PhoneNumber).HasMaxLength(9).IsUnicode(false);
                b.Property(u => u.FechaCreacion).HasDefaultValueSql("GETDATE()");
                b.Property(u => u.UltimoAcceso).IsRequired(false);
                b.Property(u => u.Estado).HasDefaultValue(false);
                b.Property(u => u.FechaCaducidadContrasena).HasColumnType("date");
            });

            // Configuración para Roles
            modelBuilder.Entity<Rol>(b =>
            {
                b.ToTable("Roles");
                b.Property(r => r.Id).HasColumnName("Id");
                b.Property(r => r.Name).HasMaxLength(256);
                b.Property(r => r.NormalizedName).HasMaxLength(256);
                b.Property(r => r.ConcurrencyStamp).HasMaxLength(500);
            });
        }
    }
}
