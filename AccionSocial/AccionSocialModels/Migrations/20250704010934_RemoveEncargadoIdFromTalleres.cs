using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccionSocialModels.Migrations
{
    /// <inheritdoc />
    public partial class RemoveEncargadoIdFromTalleres : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 1. Eliminar la FK primero (para evitar errores de dependencia)
            migrationBuilder.DropForeignKey(
                name: "FK_Talleres_Usuarios_EncargadoId",
                table: "Talleres");

            // 2. Eliminar el índice asociado a EncargadoId
            migrationBuilder.DropIndex(
                name: "IX_Talleres_EncargadoId",
                table: "Talleres");

            // 3. Eliminar la columna EncargadoId
            migrationBuilder.DropColumn(
                name: "EncargadoId",
                table: "Talleres");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // 4. En caso de rollback, recrear la columna, índice y FK
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
