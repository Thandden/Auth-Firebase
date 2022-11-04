from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional
from datetime import datetime


class Register(BaseModel):
    """Hold data for registering a new user."""

    email: EmailStr = Field()
    password: str = Field()
    password_confirm: str = Field()

    @validator("email")
    def email_validator(cls, v):
        """
        Validate email address with "@" symbol.
        """
        if "@" not in v:
            raise ValueError("Invalid email")
        return v

    @validator("password")
    def password_validator(cls, v):
        """
        Password validation for passwords less than 8 characters.
        """
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @validator("password_confirm")
    def password_confirm_validator(cls, v, values):
        """
        Ensure password and password_confirm match.
        """
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

    def payload(self):
        """
        This will be sent to the Firebase API.
        """
        return {
            "email": self.email,
            "password": self.password,
            "returnSecureToken": True,
        }


class Login(BaseModel):
    """Hold data for logging in a user."""

    email: EmailStr = Field()
    password: str = Field()

    @validator("email")
    def email_validator(cls, v):
        if "@" not in v:
            raise ValueError("Invalid email")
        return v

    @validator("password")
    def password_validator(cls, v):
        if len(v) < 1:
            raise ValueError("Password cannot be empty.")
        return v

    def payload(self):
        return {
            "email": self.email,
            "password": self.password,
            "returnSecureToken": True,
        }


class ResetPassword(BaseModel):
    """Reset password request.

    Raises:
        ValueError: Passwords do not match.
        ValueError: Password must be at least 8 characters.

    """

    oob_code: str
    password: str = Field()
    password_confirm: str = Field()

    @validator("password")
    def password_validator(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @validator("password_confirm")
    def password_confirm_validator(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

    def payload(self):
        return {"oobCode": self.oob_code, "newPassword": self.password}


class ResetPasswordEmail(BaseModel):
    """
    
    """

    email: EmailStr = Field()

    def payload(self):
        return {"requestType": "PASSWORD_RESET", "email": self.email}


class CheckOobCode(BaseModel):
    oob_code: str

    def payload(self):
        return {"oobCode": self.oob_code}


class ChangeEmail(BaseModel):
    id_token: str
    email: EmailStr = Field()

    @validator("email")
    def email_validator(cls, v):
        if "@" not in v:
            raise ValueError("Invalid email")
        return v

    def payload(self):
        return {
            "idToken": self.id_token,
            "email": self.email,
            "returnSecureToken": True,
        }


class SendEmailVerification(BaseModel):
    id_token: str

    def payload(self):
        return {"requestType": "VERIFY_EMAIL", "idToken": self.id_token}


class ConfirmEmailVerification(BaseModel):
    oob_code: str

    def payload(self):
        return {"oobCode": self.oob_code}


class DeleteAccount(BaseModel):
    id_token: str

    def payload(self):
        return {"idToken": self.id_token}


class ChangePassword(BaseModel):
    id_token: str
    password: str
    confirm_password: str

    @validator("password")
    def password_validator(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @validator("confirm_password")
    def password_confirm_validator(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

    def payload(self):
        return {
            "idToken": self.id_token,
            "password": self.password,
            "returnSecureToken": True,
        }


class FirebaseResponse(BaseModel):
    """
    Used to model the response from Firebase API calls. Optional fields so this model can be used with all calls.
    
    All objects will have a message response.

    """
    message: dict
    email: Optional[EmailStr] = None
    date: datetime = datetime.now()
    user_id: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[str] = None
    registered: Optional[bool] = None
    email_verified: Optional[bool] = None
