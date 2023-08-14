using Duende.IdentityServer.AspNetIdentity;
using Duende.IdentityServer.Services;
using MagicVilla_Identity;
using MagicVilla_Identity.Data;
using MagicVilla_Identity.IDbInitializer;
using MagicVilla_Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

string connectionString = builder.Configuration.GetConnectionString("DefaultSQLConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddScoped<IDbInitializer, DbInitializer>();

builder.Services.AddRazorPages();

IIdentityServerBuilder identityServerBuilder = builder.Services.AddIdentityServer(options =>
{
    options.Events.RaiseErrorEvents = true;
    options.Events.RaiseInformationEvents = true;
    options.Events.RaiseFailureEvents = true;
    options.Events.RaiseSuccessEvents = true;
    options.EmitStaticAudienceClaim = true;
});
identityServerBuilder.AddInMemoryIdentityResources(SD.IdentityResources);
identityServerBuilder.AddInMemoryApiScopes(SD.ApiScopes);
identityServerBuilder.AddInMemoryClients(SD.Clients);
identityServerBuilder.AddAspNetIdentity<ApplicationUser>();
identityServerBuilder.AddDeveloperSigningCredential();
identityServerBuilder.AddProfileService<ProfileService>();

builder.Services.AddScoped<IProfileService, ProfileService>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
SeedDatabase();
app.UseRouting();

app.UseIdentityServer();

app.UseAuthorization();

app.MapRazorPages();
    //.RequireAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
void SeedDatabase()
{
    using (var scope = app.Services.CreateScope())
    {
        var dbInitializer = scope.ServiceProvider.GetRequiredService<IDbInitializer>();
        dbInitializer.Initialize();
    }
}
