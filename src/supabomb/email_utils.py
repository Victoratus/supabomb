"""Email verification utilities for Supabomb."""
import re
import time
from typing import Optional
from bs4 import BeautifulSoup


class TempEmailClient:
    """Wrapper for temporary email client (mail.tm)."""

    def __init__(self, client, address, password):
        self.client = client
        self.address = address
        self.password = password


def create_temp_email():
    """Create a temporary email address using mail.tm.

    Returns:
        TempEmailClient instance

    Raises:
        Exception if temp email service is unavailable
    """
    try:
        from mailtm import MailTMClient
        import random
        import string

        # Get available domains
        domains = MailTMClient.get_domains()
        if not domains:
            raise Exception("No mail.tm domains available")

        # Generate random username
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        email_address = f"{username}@{domains[0].domain}"

        # Generate random password
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        # Create account (this returns an Account object, not a client)
        account = MailTMClient.create_account(address=email_address, password=password)

        # Create authenticated client with account and password
        client = MailTMClient(account=email_address, password=password)

        return TempEmailClient(client, email_address, password)

    except ImportError:
        raise ImportError("mailtm-python is required for email verification. Install with: pip install mailtm-python")
    except Exception as e:
        error_msg = str(e)
        if 'timeout' in error_msg.lower() or 'connection' in error_msg.lower():
            raise Exception(
                "Temporary email service (mail.tm) is currently unavailable.\n"
                "This may be due to:\n"
                "  - Network connectivity issues\n"
                "  - Service downtime\n"
                "  - Timeout\n\n"
                "Alternatives:\n"
                "  1. Try again later\n"
                "  2. Check your network connection\n"
                "  3. Manually provide an email with --email flag"
            )
        elif '429' in error_msg or 'Too Many Requests' in error_msg:
            raise Exception(
                "Rate limit exceeded for mail.tm service.\n"
                "Please wait a few minutes and try again, or use --email flag to provide your own email."
            )
        raise


def wait_for_verification_email(temp_email_client, timeout: int = 120, verbose: bool = False) -> Optional[str]:
    """Wait for Supabase verification email and extract confirmation link.

    Args:
        temp_email_client: TempEmailClient instance
        timeout: Maximum wait time in seconds
        verbose: Print debug information

    Returns:
        Verification URL or None if timeout/not found
    """
    start_time = time.time()
    check_interval = 3  # Check every 3 seconds
    check_count = 0

    try:
        while time.time() - start_time < timeout:
            check_count += 1
            # Get messages
            messages = temp_email_client.client.get_messages()

            if verbose:
                print(f"[Check #{check_count}] Found {len(messages)} message(s)")

            # Look for verification email
            for msg_info in messages:
                if verbose:
                    print(f"  - From: {msg_info.from_.address}, Subject: {msg_info.subject}")

                # Check if it's from Supabase or has verification keywords
                if ('supabase' in msg_info.from_.address.lower() or
                    'confirm' in msg_info.subject.lower() or
                    'verify' in msg_info.subject.lower()):

                    if verbose:
                        print(f"  ✓ Match found! Getting full message...")

                    # Get full message content
                    full_msg = temp_email_client.client.get_message_by_id(msg_info.id)

                    if verbose:
                        print(f"  Message details:")
                        print(f"    ID: {msg_info.id}")
                        print(f"    From: {msg_info.from_.address}")
                        print(f"    Subject: {msg_info.subject}")
                        print(f"    Created: {msg_info.createdAt}")
                        print(f"  Fetching full message content...")

                    link = extract_verification_link(full_msg, verbose=verbose)

                    if link:
                        return link

            # Wait before next check
            time.sleep(check_interval)

        return None

    except Exception as e:
        if verbose:
            print(f"Error while waiting: {e}")
        return None


def extract_verification_link(msg, verbose: bool = False) -> Optional[str]:
    """Extract verification/confirmation link from email message.

    Args:
        msg: Message object from mailtm-python
        verbose: Print debug information

    Returns:
        First verification URL found or None
    """
    # Try HTML content first
    if hasattr(msg, 'html') and msg.html:
        html_content = msg.html[0] if isinstance(msg.html, list) else msg.html

        if verbose:
            print(f"\n  [Email HTML Content]")
            print(f"  Length: {len(html_content)} characters")
            print(f"  Preview:")
            print(f"  {html_content}")
            print()

        soup = BeautifulSoup(html_content, 'html.parser')

        # Find all links with their text content
        links_found = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            if url.startswith('http'):  # Only collect http/https links, not mailto
                # Get the text content of the link
                link_text = link.get_text(strip=True)
                links_found.append((url, link_text))

        if verbose:
            print(f"  Found {len(links_found)} HTTP links in HTML:")
            for url, text in links_found:
                print(f"    - Text: '{text}' -> URL: {url[:80]}...")

        # Priority 1: Match based on link TEXT (most reliable for verification emails)
        verification_keywords = ['verify', 'confirm', 'activate', 'validation', 'complete', 'signup']
        for url, link_text in links_found:
            if any(keyword in link_text.lower() for keyword in verification_keywords):
                if verbose:
                    print(f"  ✓ Found verification link by text match: '{link_text}' -> {url[:80]}...")
                return url

        # Priority 2: Match based on URL keywords (fallback)
        for url, link_text in links_found:
            if any(keyword in url.lower() for keyword in
                   ['confirm', 'verify', 'token', 'activation', 'type=signup', 'auth']):
                if verbose:
                    print(f"  ✓ Found verification link by URL match: {url[:80]}...")
                return url

        # Priority 3: Return first non-unsubscribe link (last resort)
        for url, link_text in links_found:
            if 'unsubscribe' not in url.lower() and 'unsubscribe' not in link_text.lower():
                if verbose:
                    print(f"  ✓ Using first non-unsubscribe link: '{link_text}' -> {url[:80]}...")
                return url

        if verbose:
            print(f"  ✗ No suitable verification link found in {len(links_found)} links")

    # Fallback to plain text with regex
    content = ""
    if hasattr(msg, 'text') and msg.text:
        content = msg.text[0] if isinstance(msg.text, list) else msg.text
    elif hasattr(msg, 'html') and msg.html:
        content = msg.html[0] if isinstance(msg.html, list) else msg.html

    if verbose and content:
        print(f"\n  [Email Text Content]")
        print(f"  Length: {len(content)} characters")
        print(f"  Full text:")
        print(f"  {content}")
        print()

    url_pattern = r'https?://[^\s<>"]+(?:confirm|verify|token|activation|type=signup)[^\s<>"]*'
    urls = re.findall(url_pattern, content)

    if urls:
        if verbose:
            print(f"  ✓ Found {len(urls)} verification link(s) via regex: {urls[0][:100]}...")
        return urls[0]

    if verbose:
        print(f"  ✗ No verification URLs found")

    return None
