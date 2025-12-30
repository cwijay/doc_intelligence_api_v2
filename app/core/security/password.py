"""Password hashing and validation utilities.

Provides:
- Password hashing using bcrypt
- Password verification
- Password strength validation
- Secure password generation
"""

import re
import secrets
import string

from passlib.context import CryptContext

from app.core.config import settings

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password string
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password
        hashed_password: Previously hashed password

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength according to security requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long"

    if len(password) > settings.PASSWORD_MAX_LENGTH:
        return False, f"Password must be less than {settings.PASSWORD_MAX_LENGTH} characters long"

    # Check for at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    # Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    # Check for at least one digit
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"

    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return (
            False,
            'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)',
        )

    # Check for common patterns - expanded list based on OWASP guidelines
    common_passwords = {
        "password",
        "12345678",
        "qwerty123",
        "password123",
        "admin123",
        "letmein1",
        "welcome1",
        "monkey12",
        "dragon12",
        "master12",
        "abc12345",
        "trustno1",
        "iloveyou",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "superman",
        "michael1",
        "shadow12",
        "passw0rd",
        "p@ssword",
        "p@ssw0rd",
        "password1",
        "qwertyui",
        "asdfghjk",
        "zxcvbnm1",
        "123456ab",
        "abcd1234",
        "1234abcd",
    }
    if password.lower() in common_passwords:
        return False, "Password is too common"

    return True, ""


def generate_secure_password(length: int = 12) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (default: 12, minimum: 8)

    Returns:
        Randomly generated password
    """
    if length < 8:
        length = 8

    # Ensure password contains at least one character from each category
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*(),.?":{}|<>'

    # Start with one character from each category
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # Fill the rest with random characters from all categories
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))

    # Shuffle the password list to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def needs_rehash(hashed_password: str) -> bool:
    """
    Check if a password hash needs to be rehashed (due to algorithm updates).

    Args:
        hashed_password: The hashed password to check

    Returns:
        True if the hash needs to be updated
    """
    return pwd_context.needs_update(hashed_password)
