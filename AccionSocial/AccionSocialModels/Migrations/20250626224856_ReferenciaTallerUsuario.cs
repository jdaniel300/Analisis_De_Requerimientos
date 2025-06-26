using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccionSocialModels.Migrations
{
    /// <inheritdoc />
    public partial class ReferenciaTallerUsuario : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "EncargadoId",
                table: "Talleres",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Estado",
                table: "Talleres",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "FechaActualizacion",
                table: "Talleres",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "FechaCreacion",
                table: "Talleres",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "Objetivos",
                table: "Talleres",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_Talleres_EncargadoId",
                table: "Talleres",
                column: "EncargadoId");

            migrationBuilder.CreateIndex(
                name: "IX_Talleres_Nombre",
                table: "Talleres",
                column: "Nombre",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Talleres_Usuarios_EncargadoId",
                table: "Talleres",
                column: "EncargadoId",
                principalTable: "Usuarios",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Talleres_Usuarios_EncargadoId",
                table: "Talleres");

            migrationBuilder.DropIndex(
                name: "IX_Talleres_EncargadoId",
                table: "Talleres");

            migrationBuilder.DropIndex(
                name: "IX_Talleres_Nombre",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "EncargadoId",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "Estado",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "FechaActualizacion",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "FechaCreacion",
                table: "Talleres");

            migrationBuilder.DropColumn(
                name: "Objetivos",
                table: "Talleres");
        }
    }
}
