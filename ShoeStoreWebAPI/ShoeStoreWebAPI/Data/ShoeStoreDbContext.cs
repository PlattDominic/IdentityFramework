using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShoeStoreWebAPI.Models;

namespace ShoeStoreWebAPI.Data
{
    public class ShoeStoreDbContext : IdentityDbContext<ApplicationUser>
    {
        public ShoeStoreDbContext(DbContextOptions<ShoeStoreDbContext> options) : base(options)
        {
        }

        public DbSet<ShoeModel> Shoes { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
