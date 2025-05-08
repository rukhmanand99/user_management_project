# app/security.py
from builtins import Exception, ValueError, bool, int, str
import secrets
import bcrypt
from logging import getLogger
import jwt
from jwt import PyJWTError
from datetime import datetime, timedelta
from fastapi import HTTPException

# Set up logging
logger = getLogger(__name__)

# Constants for JWT functionality
SECRET_KEY = "your_secret_key"  # Replace with your actual secret key
ALGORITHM = "HS256"  # Standard algorithm for signing tokens

def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hashes a password using bcrypt with a specified cost factor.
    
    Args:
        password (str): The plain text password to hash.
        rounds (int): The cost factor that determines the computational cost of hashing.

    Returns:
        str: The hashed password.

    Raises:
        ValueError: If hashing the password fails.
    """
    try:
        salt = bcrypt.gensalt(rounds=rounds)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    except Exception as e:
        logger.error("Failed to hash password: %s", e)
        raise ValueError("Failed to hash password") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a hashed password.
    
    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The bcrypt hashed password.

    Returns:
        bool: True if the password is correct, False otherwise.

    Raises:
        ValueError: If the hashed password format is incorrect or the function fails to verify.
    """
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        raise ValueError("Authentication process encountered an unexpected error") from e

def generate_verification_token():
    return secrets.token_urlsafe(16)  # Generates a secure 16-byte URL-safe token

    """
    Generates a secure token for verification purposes (e.g., email verification).
    Returns:
        str: A secure URL-safe token.
    """
    return secrets.token_urlsafe(16)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)) -> str:
    """
    Creates a JWT access token with an expiration time.
    Args:
        data (dict): The payload to encode in the token.
        expires_delta (timedelta): The duration before the token expires.
    Returns:
        str: The JWT token as a string.
    """
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info("Access token created for data: %s", data)
        return encoded_jwt
    except Exception as e:
        logger.error("Failed to create access token: %s", e)
        raise HTTPException(status_code=500, detail="Failed to generate token")

from jwt import ExpiredSignatureError, MissingRequiredClaimError, PyJWTError

def verify_access_token(token: str):
    """
    Verifies a JWT token and checks its validity.
    Args:
        token (str): The JWT token to verify.
    Returns:
        dict: The decoded payload if valid.
    Raises:
        HTTPException: If the token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]}
        )
        return payload
    except ExpiredSignatureError:
        logger.warning("Token has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except MissingRequiredClaimError as e:
        logger.error("Missing required claim: %s", e)
        raise HTTPException(status_code=401, detail="Token missing required claim: exp")
    except PyJWTError as e:
        logger.error("Invalid token: %s", e)
        raise HTTPException(status_code=401, detail="Invalid token")
