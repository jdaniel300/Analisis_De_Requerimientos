using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccionSocialModels.Migrations
{
    /// <inheritdoc />
    public partial class RelacionTalleresSesionesParticipantes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Participantes_Talleres_IdTaller",
                table: "Participantes");

            migrationBuilder.RenameColumn(
                name: "IdTaller",
                table: "Participantes",
                newName: "IdSesion");

            migrationBuilder.RenameIndex(
                name: "IX_Participantes_IdUsuario_IdTaller",
                table: "Participantes",
                newName: "IX_Participantes_IdUsuario_IdSesion");

            migrationBuilder.RenameIndex(
                name: "IX_Participantes_IdTaller",
                table: "Participantes",
                newName: "IX_Participantes_IdSesion");

            migrationBuilder.AddColumn<int>(
                name: "SesionId",
                table: "Participantes",
                type: "int",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Sesiones",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    IdTaller = table.Column<int>(type: "int", nullable: false),
                    Fecha = table.Column<DateOnly>(type: "date", nullable: false),
                    HoraInicio = table.Column<TimeSpan>(type: "time", nullable: false),
                    HoraFin = table.Column<TimeSpan>(type: "time", nullable: false),
                    Estado = table.Column<bool>(type: "bit", nullable: false, defaultValue: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sesiones", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Sesiones_Talleres_IdTaller",
                        column: x => x.IdTaller,
                        principalTable: "Talleres",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Participantes_SesionId",
                table: "Participantes",
                column: "SesionId");

            migrationBuilder.CreateIndex(
                name: "IX_Sesiones_Fecha",
                table: "Sesiones",
                column: "Fecha");

            migrationBuilder.CreateIndex(
                name: "IX_Sesiones_IdTaller",
                table: "Sesiones",
                column: "IdTaller");

            migrationBuilder.AddForeignKey(
                name: "FK_Participantes_Sesiones_IdSesion",
                table: "Participantes",
                column: "IdSesion",
                principalTable: "Sesiones",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_Participantes_Sesiones_SesionId",
                table: "Participantes",
                column: "SesionId",
                principalTable: "Sesiones",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Participantes_Sesiones_IdSesion",
                table: "Participantes");

            migrationBuilder.DropForeignKey(
                name: "FK_Participantes_Sesiones_SesionId",
                table: "Participantes");

            migrationBuilder.DropTable(
                name: "Sesiones");

            migrationBuilder.DropIndex(
                name: "IX_Participantes_SesionId",
                table: "Participantes");

            migrationBuilder.DropColumn(
                name: "SesionId",
                table: "Participantes");

            migrationBuilder.RenameColumn(
                name: "IdSesion",
                table: "Participantes",
                newName: "IdTaller");

            migrationBuilder.RenameIndex(
                name: "IX_Participantes_IdUsuario_IdSesion",
                table: "Participantes",
                newName: "IX_Participantes_IdUsuario_IdTaller");

            migrationBuilder.RenameIndex(
                name: "IX_Participantes_IdSesion",
                table: "Participantes",
                newName: "IX_Participantes_IdTaller");

            migrationBuilder.AddForeignKey(
                name: "FK_Participantes_Talleres_IdTaller",
                table: "Participantes",
                column: "IdTaller",
                principalTable: "Talleres",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
