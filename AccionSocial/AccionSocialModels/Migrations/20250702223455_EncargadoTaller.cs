using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccionSocialModels.Migrations
{
    /// <inheritdoc />
    public partial class EncargadoTaller : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Talleres_Usuarios_EncargadoId",
                table: "Talleres");

            migrationBuilder.DropIndex(
                name: "IX_Talleres_EncargadoId",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "EncargadoId",
                table: "Talleres");

            migrationBuilder.CreateTable(
                name: "EncargadosTaller",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    IdTaller = table.Column<int>(type: "int", nullable: false),
                    IdUsuario = table.Column<int>(type: "int", nullable: false),
                    FechaAsigmacion = table.Column<DateTime>(type: "datetime", nullable: false, defaultValueSql: "GETDATE()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EncargadosTaller", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EncargadosTaller_Talleres_IdTaller",
                        column: x => x.IdTaller,
                        principalTable: "Talleres",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_EncargadosTaller_Usuarios_IdUsuario",
                        column: x => x.IdUsuario,
                        principalTable: "Usuarios",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EncargadosTaller_IdUsuario",
                table: "EncargadosTaller",
                column: "IdUsuario");

            migrationBuilder.CreateIndex(
                name: "IX_Unique_Encargado_Taller",
                table: "EncargadosTaller",
                columns: new[] { "IdTaller", "IdUsuario" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EncargadosTaller");

            migrationBuilder.AddColumn<int>(
                name: "EncargadoId",
                table: "Talleres",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_Talleres_EncargadoId",
                table: "Talleres",
                column: "EncargadoId");

            migrationBuilder.AddForeignKey(
                name: "FK_Talleres_Usuarios_EncargadoId",
                table: "Talleres",
                column: "EncargadoId",
                principalTable: "Usuarios",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
