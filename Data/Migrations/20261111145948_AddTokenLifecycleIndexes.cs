using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompareShopAuthAPI.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTokenLifecycleIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "PasswordResetPins",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "EmailVerifications",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetPins_UserId_UsedAt",
                table: "PasswordResetPins",
                columns: new[] { "UserId", "UsedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EmailVerifications_UserId_UsedAt",
                table: "EmailVerifications",
                columns: new[] { "UserId", "UsedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PasswordResetPins_UserId_UsedAt",
                table: "PasswordResetPins");

            migrationBuilder.DropIndex(
                name: "IX_EmailVerifications_UserId_UsedAt",
                table: "EmailVerifications");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "PasswordResetPins",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "EmailVerifications",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");
        }
    }
}
