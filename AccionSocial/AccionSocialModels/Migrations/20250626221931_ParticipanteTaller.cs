using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccionSocialModels.Migrations
{
    /// <inheritdoc />
    public partial class ParticipanteTaller : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Participantes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    IdUsuario = table.Column<int>(type: "int", nullable: false),
                    IdTaller = table.Column<int>(type: "int", nullable: false),
                    FechaInscripcion = table.Column<DateTime>(type: "datetime", nullable: false),
                    Estado = table.Column<bool>(type: "bit", maxLength: 50, nullable: false, defaultValue: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Participantes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Participantes_Talleres_IdTaller",
                        column: x => x.IdTaller,
                        principalTable: "Talleres",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Participantes_Usuarios_IdUsuario",
                        column: x => x.IdUsuario,
                        principalTable: "Usuarios",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Participantes_IdTaller",
                table: "Participantes",
                column: "IdTaller");

            migrationBuilder.CreateIndex(
                name: "IX_Participantes_IdUsuario_IdTaller",
                table: "Participantes",
                columns: new[] { "IdUsuario", "IdTaller" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Participantes");
        }
    }
}
