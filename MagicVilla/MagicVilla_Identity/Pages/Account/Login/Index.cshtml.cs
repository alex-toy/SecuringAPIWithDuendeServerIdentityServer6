using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Test;
using MagicVilla_Identity.Data;
using MagicVilla_Identity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace UI.Pages.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _db;
    //private readonly TestUserStore _users;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;

    public ViewModel View { get; set; }
        
    [BindProperty]
    public InputModel Input { get; set; }

    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        //TestUserStore users = null,
        UserManager<ApplicationUser> userManager = null,
        SignInManager<ApplicationUser> signInManager = null,
        RoleManager<IdentityRole> roleManager = null,
        ApplicationDbContext db = null)
    {
        // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
        //_users = users ?? throw new Exception("Please call 'AddTestUsers(TestUsers.Users)' on the IIdentityServerBuilder in Startup or remove the TestUserStore from the AccountController.");

        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _db = db;
    }

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        await BuildModelAsync(returnUrl);
            
        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }
        
    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        AuthorizationRequest? authorizationRequest = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            if (authorizationRequest == null) return Redirect("~/");

            await _interaction.DenyAuthorizationAsync(authorizationRequest, AuthorizationError.AccessDenied);

            if (authorizationRequest.IsNativeClient()) return this.LoadingPage(Input.ReturnUrl);

            return Redirect(Input.ReturnUrl);
        }

        if (!ModelState.IsValid)
        {
            // something went wrong, show form with error
            await BuildModelAsync(Input.ReturnUrl);
            return Page();
        }

        // validate username/password against in-memory store
        SignInResult result = await GetSignInResult();

        if (!result.Succeeded)
        {
            var failureEvent = new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId: authorizationRequest?.Client.ClientId);
            await _events.RaiseAsync(failureEvent);
            ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);
        }

        ApplicationUser? user = GetApplicationUser();
        var successEvent = new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: authorizationRequest?.Client.ClientId);
        await _events.RaiseAsync(successEvent);

        // issue authentication cookie with subject ID and username
        IdentityServerUser isuser = new IdentityServerUser(user.Id)
        {
            DisplayName = user.UserName
        };

        if (authorizationRequest != null)
        {
            if (authorizationRequest.IsNativeClient()) return this.LoadingPage(Input.ReturnUrl);
            return Redirect(Input.ReturnUrl);
        }

        // request for a local page
        if (Url.IsLocalUrl(Input.ReturnUrl)) return Redirect(Input.ReturnUrl);
        if (string.IsNullOrEmpty(Input.ReturnUrl)) return Redirect("~/");

        // user might have clicked on a malicious link - should be logged
        throw new Exception("invalid return URL");
    }

    private async Task<SignInResult> GetSignInResult()
    {
        return await _signInManager.PasswordSignInAsync(Input.Username, Input.Password, Input.RememberLogin, lockoutOnFailure: false);
    }

    private ApplicationUser? GetApplicationUser()
    {
        return _db.ApplicationUsers.FirstOrDefault(u => u.UserName.ToLower() == Input.Username.ToLower());
    }

    private async Task BuildModelAsync(string returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };
            
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            View = new ViewModel
            {
                EnableLocalLogin = local,
            };

            Input.Username = context?.LoginHint;

            if (!local)
            {
                View.ExternalProviders = new[] { new ViewModel.ExternalProvider { AuthenticationScheme = context.IdP } };
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            }).ToList();

        var dyanmicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            {
                AuthenticationScheme = x.Scheme,
                DisplayName = x.DisplayName
            });
        providers.AddRange(dyanmicSchemes);


        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }
}