using AccionSocialModels.Relaciones;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;



namespace AccionSocialModels
{
    public class MyIdentityDbContext : IdentityDbContext<Usuario, Rol, int>
    {
        public MyIdentityDbContext(DbContextOptions<MyIdentityDbContext> options)
            : base(options) { }

       public DbSet<Taller> Talleres { get; set; }
        public DbSet<EncargadoTaller> EncargadoTaller { get; set; }
        public DbSet<Participantes> Participantes { get; set; }

        public DbSet<Sesion> Sesion { get; set; }
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
                b.Property(t => t.Estado).HasDefaultValue(true); // Si el estado tiene valores fijos
                b.Property(t => t.Objetivos).HasMaxLength(2000); // Para limitar el tamaño
                b.Property(t => t.FechaCreacion).IsRequired(); // Para asegurar fecha de creación
                b.Property(t => t.FechaActualizacion).IsRequired(); // Para asegurar fecha de actualización// Configuración de la relación con Usuario

                // Índice opcional para el nombre del taller
                b.HasIndex(t => t.Nombre).IsUnique();


            });

            modelBuilder.Entity<Sesion>(b =>
            {
                b.ToTable("Sesiones");

                // Clave primaria
                b.HasKey(s => s.Id);
                b.Property(s => s.Id).ValueGeneratedOnAdd().IsRequired();

                // Propiedades específicas de sesión
                b.Property(s => s.Fecha).IsRequired();
                b.Property(s => s.HoraInicio).IsRequired();
                b.Property(s => s.HoraFin).IsRequired();
                b.Property(s => s.Estado).HasDefaultValue(true);

                // Relación con Taller
                b.HasOne(s => s.Taller)
                    .WithMany(t => t.Sesiones)
                    .HasForeignKey(s => s.IdTaller)
                    .OnDelete(DeleteBehavior.Cascade);

                // Índice para búsquedas por fecha
                b.HasIndex(s => s.Fecha);
            });

            modelBuilder.Entity<Participantes>(b =>
            {
                b.ToTable("Participantes");

                // Configuración EXPLÍCITA de la clave primaria (esto faltaba)
                b.HasKey(p => p.Id);
                b.Property(p => p.Id).ValueGeneratedOnAdd().IsRequired();

                // Configuración de propiedades
                b.Property(p => p.IdUsuario).IsRequired();
                b.Property(p => p.IdSesion).IsRequired();

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

                b.HasOne(p => p.Sesion)
                    .WithMany()
                    .HasForeignKey(p => p.IdSesion)
                    .OnDelete(DeleteBehavior.Restrict);

                // Índice único opcional
                b.HasIndex(p => new { p.IdUsuario, p.IdSesion })
                    .IsUnique();
            });

            modelBuilder.Entity<EncargadoTaller>(b =>
            {
                b.ToTable("EncargadosTaller"); // Nombre de tabla en plural

                // Configuración de clave primaria
                b.HasKey(e => e.Id);
                b.Property(e => e.Id)
                    .ValueGeneratedOnAdd()
                    .IsRequired();

                // Configuración de claves foráneas
                b.Property(e => e.IdTaller)
                    .IsRequired();

                b.Property(e => e.IdUsuario)
                    .IsRequired();

                // Configuración de propiedad de fecha
                b.Property(e => e.FechaAsigmacion) // Nota: Hay un typo en "Asigmacion" (debería ser "Asignacion")
                    .IsRequired()
                    .HasColumnType("datetime")
                    .HasDefaultValueSql("GETDATE()"); // Valor por defecto fecha actual

                // Configuración de relaciones
                b.HasOne(e => e.taller) // Corrección: usar "Taller" (mayúscula) para coincidir con la propiedad
                    .WithMany() // Asumiendo que Taller no tiene colección de EncargadoTaller
                    .HasForeignKey(e => e.IdTaller)
                    .OnDelete(DeleteBehavior.Cascade); // O Restrict según necesidades

                b.HasOne(e => e.usuario) // Corrección: usar "Usuario" (mayúscula)
                    .WithMany() // Asumiendo que Usuario no tiene colección de EncargadoTaller
                    .HasForeignKey(e => e.IdUsuario)
                    .OnDelete(DeleteBehavior.Cascade); // O Restrict según necesidades

                // Índice único para evitar asignaciones duplicadas
                b.HasIndex(e => new { e.IdTaller, e.IdUsuario })
                    .IsUnique()
                    .HasDatabaseName("IX_Unique_Encargado_Taller");
            });

            

        }
    }
}
