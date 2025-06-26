using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;



namespace AccionSocialModels
{
    public class MyIdentityDbContext : IdentityDbContext<Usuario, Rol, int>
    {
        public MyIdentityDbContext(DbContextOptions<MyIdentityDbContext> options)
            : base(options) { }

       public DbSet<Taller> Talleres { get; set; }
        public DbSet<Participantes> Participantes { get; set; }
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

            modelBuilder.Entity<Taller>(b =>
            {
                b.ToTable("Talleres");

                // Configuración de la clave primaria
                b.HasKey(t => t.Id);
                b.Property(t => t.Id).ValueGeneratedOnAdd().IsRequired(); // Autoincremental 
                                                                                // Configuración de las propiedades
                b.Property(t => t.Nombre).HasMaxLength(200).IsRequired();
                b.Property(t => t.Descripcion).HasMaxLength(1000).IsRequired();
                b.Property(t => t.Estado).HasMaxLength(50); // Si el estado tiene valores fijos
                b.Property(t => t.Objetivos).HasMaxLength(2000); // Para limitar el tamaño
                b.Property(t => t.FechaCreacion).IsRequired(); // Para asegurar fecha de creación
                b.Property(t => t.FechaActualizacion).IsRequired(); // Para asegurar fecha de actualización// Configuración de la relación con Usuario
                b.HasOne(t => t.Encargado)
                    .WithMany()
                    .HasForeignKey(t => t.EncargadoId)
                    .OnDelete(DeleteBehavior.Restrict); // Restrict para evitar borrados en cascada

                // Índice opcional para el nombre del taller
                b.HasIndex(t => t.Nombre).IsUnique();

            });
            modelBuilder.Entity<Participantes>(b =>
            {
                b.ToTable("Participantes");

                // Configuración EXPLÍCITA de la clave primaria (esto faltaba)
                b.HasKey(p => p.Id);
                b.Property(p => p.Id).ValueGeneratedOnAdd().IsRequired();

                // Configuración de propiedades
                b.Property(p => p.IdUsuario).IsRequired();
                b.Property(p => p.IdTaller).IsRequired();

                b.Property(p => p.FechaInscripcion)
                    .IsRequired()
                    .HasColumnType("datetime");

                b.Property(p => p.Estado)
                    .IsRequired()
                    .HasMaxLength(50)
                    .HasDefaultValue("true");

                // Configuración de relaciones
                b.HasOne(p => p.Usuario)
                    .WithMany()
                    .HasForeignKey(p => p.IdUsuario)
                    .OnDelete(DeleteBehavior.Restrict);

                b.HasOne(p => p.Taller)
                    .WithMany()
                    .HasForeignKey(p => p.IdTaller)
                    .OnDelete(DeleteBehavior.Restrict);

                // Índice único opcional
                b.HasIndex(p => new { p.IdUsuario, p.IdTaller })
                    .IsUnique();
            });

        }
    }
}
