using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShoeStoreWebAPI.Data;
using ShoeStoreWebAPI.Models;
using System.Security.Claims;

namespace ShoeStoreWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ShoeController : ControllerBase
    {
        private readonly ShoeStoreDbContext _dbContext;
        private readonly UserManager<ApplicationUser> _userManager;

        public ShoeController(ShoeStoreDbContext dbContext, UserManager<ApplicationUser> userManager)
        {
            _dbContext = dbContext;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> GetShoes() => Ok(await _dbContext.Shoes.ToListAsync());

        [HttpGet]
        [Route("{id:guid}")]
        public async Task<IActionResult> GetShoe(Guid id)
        {
            var cd = await _dbContext.Shoes.FindAsync(id);

            return cd == null ? NotFound() : Ok(cd);
        }

        [Authorize(Roles = UserRoles.Seller)]
        [HttpPost]
        public async Task<IActionResult> AddShoe(AddShoeForm addShoeForm)
        {
            //if (await _userManager.FindByNameAsync(addShoeForm.SellerUsername) == null)
            //    return NotFound($"Could not find a user with the provided seller username: { addShoeForm.SellerUsername }");

            var newShoe = new ShoeModel
            {
                Id = Guid.NewGuid(),
                SellerUsername = HttpContext.User.Identity?.Name,
                Brand = addShoeForm.Brand,
                Name = addShoeForm.Name,
                Price = addShoeForm.Price,
                Size = addShoeForm.Size
            };

            await _dbContext.AddAsync(newShoe);
            await _dbContext.SaveChangesAsync();
            
            return Ok(newShoe);
        }

        [Authorize(Roles = $"{UserRoles.Seller},{UserRoles.Admin}")]
        [HttpPut]
        [Route("{id:guid}")]
        public async Task<IActionResult> UpdateShoe(Guid id, UpdateShoeForm updateShoeForm)
        {
            var shoe = await _dbContext.Shoes.FindAsync(id);

            if (shoe?.SellerUsername != HttpContext?.User?.Identity?.Name && !HttpContext.User.IsInRole(UserRoles.Admin))
                return Unauthorized("You cannot update a shoe item that is not under your username");

            if (shoe == null) 
                return NotFound();

            shoe.Brand = updateShoeForm.Brand;
            shoe.Name = updateShoeForm.Name;
            shoe.Price = updateShoeForm.Price;
            shoe.Size = updateShoeForm.Size;

            await _dbContext.SaveChangesAsync();
            return Ok(shoe);
        }

        [Authorize(Roles = $"{UserRoles.Seller},{UserRoles.Admin}")]
        [HttpDelete]
        [Route("{id:guid}")]
        public async Task<IActionResult> DeleteShoe(Guid id)
        {
            var shoe = await _dbContext.Shoes.FindAsync(id);
            Console.WriteLine(HttpContext.User.IsInRole(UserRoles.Seller));

            if (shoe?.SellerUsername != HttpContext.User.Identity?.Name && !HttpContext.User.IsInRole(UserRoles.Admin))
                return Unauthorized("You cannot delete a shoe item that is not under your username");

            if (shoe == null)
                return NotFound();

            _dbContext.Remove(shoe);
            await _dbContext.SaveChangesAsync();

            return Ok(shoe);
        }


    }
}
