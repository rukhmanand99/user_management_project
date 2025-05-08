import pytest
from uuid import uuid4
from app.models.user_model import UserRole, User
from app.services.user_service import UserService
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_check_password_validity():
    """Test validating password rules."""
    assert UserService.validate_password("ValidPassword1!") is True
    assert UserService.validate_password("short") is False
    assert UserService.validate_password("alllowercase1!") is False
    assert UserService.validate_password("NOLOWERCASE1!") is False
    assert UserService.validate_password("NoSpecialChar123") is False

@pytest.mark.asyncio
async def test_get_user_by_email(db_session: AsyncSession):
    """Test fetching a user by email."""
    user = User(
        email="email@example.com",
        hashed_password="hashedpassword123",
        nickname="testnick",
        role=UserRole.ANONYMOUS,
    )
    db_session.add(user)
    await db_session.commit()
    fetched_user = await UserService.get_by_email(db_session, "email@example.com")
    assert fetched_user is not None
    assert fetched_user.email == "email@example.com"


@pytest.mark.asyncio
async def test_get_user_by_invalid_email(db_session: AsyncSession):
    """Test fetching a user by an invalid email."""
    fetched_user = await UserService.get_by_email(db_session, "invalid@example.com")
    assert fetched_user is None


@pytest.mark.asyncio
async def test_get_user_by_id(db_session: AsyncSession):
    """Test fetching a user by ID."""
    user = User(
        email="email2@example.com",
        hashed_password="hashedpassword123",
        nickname="testnick2",
        role=UserRole.MANAGER,
    )
    db_session.add(user)
    await db_session.commit()
    fetched_user = await UserService.get_by_id(db_session, user.id)
    assert fetched_user is not None
    assert fetched_user.id == user.id

@pytest.mark.asyncio
async def test_create_user(db_session: AsyncSession):
    """Test creating a user."""
    mock_email_service = AsyncMock()

    # Create the first user (should be assigned ADMIN role)
    user_data_1 = {
        "email": "admin.user@example.com",
        "password": "ValidPassword1!",
        "nickname": None,
        "role": UserRole.AUTHENTICATED,  # Requested role
    }
    user_1 = await UserService.create(db_session, user_data_1, mock_email_service)
    await db_session.commit()

    assert user_1.email == "admin.user@example.com"
    assert user_1.nickname is not None
    assert user_1.role == UserRole.ADMIN  # First user is assigned ADMIN

    # Create a second user (should get AUTHENTICATED role)
    user_data_2 = {
        "email": "test.user@example.com",
        "password": "ValidPassword1!",
        "nickname": None,
        "role": UserRole.AUTHENTICATED,
    }
    user_2 = await UserService.create(db_session, user_data_2, mock_email_service)
    await db_session.commit()

    assert user_2.email == "test.user@example.com"
    assert user_2.nickname is not None
    assert user_2.role == UserRole.AUTHENTICATED  # Second user gets AUTHENTICATED

    # Check that the email service was called only for the second user
    assert mock_email_service.send_verification_email.call_count == 1

@pytest.mark.asyncio
async def test_update_user_role(db_session: AsyncSession):
    """Test updating a user's role."""
    user = User(
        email="roleuser@example.com",
        hashed_password="hashedpassword123",
        nickname="roleuser",
        role=UserRole.AUTHENTICATED,
    )
    db_session.add(user)
    await db_session.commit()
    updated_user = await UserService.update(db_session, user.id, {"role": UserRole.ADMIN.name})
    assert updated_user.role == UserRole.ADMIN


@pytest.mark.asyncio
async def test_lock_user_account(db_session: AsyncSession):
    """Test locking a user account."""
    user = User(
        email="lockuser@example.com",
        hashed_password="hashedpassword123",
        nickname="lockuser",
        role=UserRole.AUTHENTICATED,
    )
    db_session.add(user)
    await db_session.commit()
    user.lock_account()
    assert user.is_locked is True


@pytest.mark.asyncio
async def test_delete_user(db_session: AsyncSession):
    """Test deleting a user."""
    user = User(
        email="deleteuser@example.com",
        hashed_password="hashedpassword123",
        nickname="deleteuser",
        role=UserRole.AUTHENTICATED,
    )
    db_session.add(user)
    await db_session.commit()
    result = await UserService.delete(db_session, user.id)
    assert result is True

@pytest.mark.asyncio
async def test_get_user_by_invalid_id(db_session: AsyncSession):
    """Test fetching a user by an invalid ID."""
    fetched_user = await UserService.get_by_id(db_session, uuid4())
    assert fetched_user is None
    
@pytest.mark.asyncio
async def test_unlock_user_account(db_session: AsyncSession):
    """Test unlocking a user account."""
    user = User(
        email="unlockuser@example.com",
        hashed_password="hashedpassword123",
        nickname="unlockuser",
        is_locked=True,
        role=UserRole.MANAGER,
    )
    db_session.add(user)
    await db_session.commit()
    user.unlock_account()
    assert user.is_locked is False
