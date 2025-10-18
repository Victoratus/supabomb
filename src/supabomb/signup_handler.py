"""User signup and email verification workflow."""
import random
import string
import requests
from typing import Optional, Tuple, Dict, Any
from rich.console import Console
from rich.table import Table
from rich import box
from .email_utils import create_temp_email, wait_for_verification_email


console = Console()


def generate_random_credentials() -> Tuple[str, str]:
    """Generate random email and password for testing.

    Returns:
        Tuple of (email, password)
    """
    random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"test_{random_id}@supabomb.local"
    password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%', k=16))
    return email, password


def check_signup_configuration(client) -> Tuple[bool, Optional[str], bool]:
    """Check if signup is enabled and if email verification is required.

    Args:
        client: SupabaseClient instance

    Returns:
        Tuple of (success, error_message, requires_verification)
    """
    # Get auth settings
    success, settings, error = client.get_auth_settings()

    if not success:
        return False, f"Failed to fetch settings: {error}", False

    # Check if signup is disabled
    if settings.get('disable_signup'):
        return False, "Signups are disabled on this instance", False

    # Check if email auth is enabled
    if not settings.get('external', {}).get('email'):
        return False, "Email authentication is disabled", False

    # Check if email verification is required
    mailer_autoconfirm = settings.get('mailer_autoconfirm', False)

    return True, None, not mailer_autoconfirm


def signup_with_verification(client, credentials, email: Optional[str] = None,
                             password: Optional[str] = None,
                             auto_verify: bool = False,
                             verbose: bool = False) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Sign up a user with optional automatic email verification.

    Args:
        client: SupabaseClient instance
        credentials: Supabase credentials
        email: Optional email (generated if not provided)
        password: Optional password (generated if not provided)
        auto_verify: Automatically verify email using temp email service
        verbose: Show detailed debug information

    Returns:
        Tuple of (success, user_data, error_message)
    """
    # Check signup configuration
    signup_ok, error, requires_verification = check_signup_configuration(client)

    if not signup_ok:
        return False, None, error

    # Handle email verification requirement
    temp_email_obj = None

    if requires_verification:
        if auto_verify:
            console.print("[bold cyan]ℹ[/bold cyan] Email verification required - using temporary email service")
            try:
                temp_email_obj = create_temp_email()
                email = temp_email_obj.address
                console.print(f"[dim]Created temporary email:[/dim] {email}")
            except Exception as e:
                return False, None, f"Failed to create temporary email: {str(e)}"
        else:
            console.print("[bold yellow]Warning:[/bold yellow] Email verification is required")
            console.print("Signup will succeed but you won't get an access token immediately")
            console.print("Use --verify-email flag to automatically verify using temp email service")
            console.print("This tool works best with instances that have email autoconfirm enabled\n")

    # Generate credentials if not provided
    if not email or not password:
        gen_email, gen_password = generate_random_credentials()
        if not email:
            email = gen_email
            console.print(f"[dim]Generated email:[/dim] {email}")
        if not password:
            password = gen_password
            console.print(f"[dim]Generated password:[/dim] {password}")

    # Attempt signup
    console.print(f"\n[bold cyan]Registering user:[/bold cyan] {email}")
    with console.status("[bold green]Creating account..."):
        success, response, error = client.signup_user(email, password)

    if not success:
        return False, None, f"Signup failed: {error}"

    # Check if we got immediate access
    if 'access_token' in response:
        console.print("[bold green]✓[/bold green] Signup successful! (Email verification not required)")
        return True, {
            'email': email,
            'password': password,
            'access_token': response['access_token'],
            'refresh_token': response['refresh_token'],
            'user_id': response['user']['id'],
            'user': response['user']
        }, None

    # Email verification required
    if temp_email_obj:
        # Use temp email to verify
        console.print("[bold cyan]⏳[/bold cyan] Account created, waiting for verification email...")
        console.print(f"User ID: {response.get('id')}")

        if verbose:
            console.print("[dim]Checking for verification email every 3 seconds (verbose mode enabled)...[/dim]")
        else:
            console.print("[dim]Checking for verification email every 3 seconds...[/dim]")

        verification_url = wait_for_verification_email(temp_email_obj, timeout=180, verbose=verbose)

        if not verification_url:
            return False, None, "Timeout: No verification email received"

        console.print(f"[bold green]✓[/bold green] Verification email received!")
        console.print(f"[dim]Verification URL:[/dim] {verification_url}")

        # Follow the verification link
        with console.status("[bold green]Verifying email..."):
            try:
                verify_response = requests.get(
                    verification_url,
                    timeout=30,
                    allow_redirects=True,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (compatible; Supabomb/1.0)',
                        'apikey': credentials.anon_key
                    }
                )
                if 200 <= verify_response.status_code < 400:
                    console.print("[bold green]✓[/bold green] Email verified successfully!")
                else:
                    console.print(f"[bold yellow]⚠[/bold yellow] Email verification may not have completed (status {verify_response.status_code})")
                    console.print("[dim]Attempting login to check if verification succeeded...[/dim]")
            except Exception as e:
                console.print(f"[bold yellow]⚠[/bold yellow] Verification request failed: {e}")
                console.print("[dim]Attempting login anyway...[/dim]")

        # Now login to get access token
        console.print("\n[bold cyan]Logging in to get access token...[/bold cyan]")
        with console.status("[bold green]Authenticating..."):
            success, login_response, error = client.login_user(email, password)

        if not success:
            return False, None, f"Login failed after verification: {error}"

        console.print("[bold green]✓[/bold green] Login successful!")

        return True, {
            'email': email,
            'password': password,
            'access_token': login_response['access_token'],
            'refresh_token': login_response['refresh_token'],
            'user_id': login_response['user']['id'],
            'user': login_response['user']
        }, None

    else:
        console.print("[bold yellow]⚠[/bold yellow] Account created but email verification required")
        console.print(f"User ID: {response.get('id')}")
        console.print("Check email for confirmation link (note: test emails won't receive actual emails)")
        console.print("Use --verify-email flag to automatically verify using temp email service")
        console.print("\n[dim]This account cannot be used for authenticated queries until verified[/dim]")
        return False, None, "Email verification required - use --verify-email flag"


def display_user_info(user_data: Dict[str, Any], cache_file: str):
    """Display user information in a formatted table.

    Args:
        user_data: Dictionary with user information
        cache_file: Path to cache file
    """
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("User ID", user_data['user_id'])
    table.add_row("Email", user_data['email'])
    table.add_row("Password", user_data['password'])
    table.add_row("Role", user_data['user'].get('role', 'N/A'))
    table.add_row("Created", user_data['user'].get('created_at', 'N/A'))

    console.print()
    console.print(table)
    console.print(f"\n[dim]💾 Session saved to {cache_file}[/dim]")
    console.print("[bold green]You can now run enum/query/test commands with authenticated access[/bold green]")
