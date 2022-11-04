import requests
from utils import (
    Login,
    Register,
    ResetPasswordEmail,
    FirebaseResponse,
    CheckOobCode,
    ResetPassword,
    ChangeEmail,
    SendEmailVerification,
    DeleteAccount,
    ConfirmEmailVerification,
    ChangePassword,
)
from datetime import datetime


class Auth:
    def __init__(self, key: str) -> None:
        """Initialise the class with the project API Key

        Args:
            key (str): Project API Key
        """
        self.key = key

    def return_message(self, status: str, result: str) -> dict:
        """Returns a message to the user.

        Args:
            status (str): type of message. Error or success.
            message (str): message body.

        Returns:
            dict: returns the message as a dictionary.
        """
        return {"status": status, "result": result}

    def firebase_call(self, payload: dict, option: str) -> dict:
        """Calls the Firebase HTTP API.

        Args:
            payload (dict): Dictionary to post with the request.
            option (str): Which URL to use. The string will be built into the URL with f strings.

        Raises:
            ValueError: Will use the message function if the the API calls returns an error.

        Returns:
            dict: Returns the JSON body from the API call.
        """
        build_url = f"https://identitytoolkit.googleapis.com/v1/accounts:{option}?key={self.key}"
        r = requests.post(build_url, json=payload)
        if r.status_code == 200:
            return r.json()
        raise ValueError(r.json()["error"]["message"])

    def login(self, email: str, password: str) -> object:
        """Login in the user.

        Args:
            email (str): User's email.
            password (str): User's password.

        Returns:
            object: Returns an object that's built from the API response. Items needed like user_id can be quickly accessed.
        """
        try:
            login = Login(email=email, password=password)
            firebase = self.firebase_call(
                payload=login.payload(), option="signInWithPassword"
            )
            return FirebaseResponse(
                message=self.return_message(status="success", result="Logged in successfully."),
                user_id=firebase["localId"],
                email=firebase["email"],
                id_token=firebase["idToken"],
                refresh_token=firebase["refreshToken"],
                expires_in=firebase["expiresIn"],
                
            )

        except ValueError as e:
            print(e)
            return FirebaseResponse(
                message={"status": "error", "result": e},
            )

    def register(self, email: str, password: str, password_confirm: str) -> dict:
        """Registers a new user.

        Args:
            email (str): User's email address.
            password (str): User's password.
            password_confirm (str): Confirmation password.

        Returns:
            dict: Returns an object build from the API response.
        """
        try:
            register = Register(
                email=email, password=password, password_confirm=password_confirm
            )
            firebase = self.firebase_call(payload=register.payload(), option="signUp")
            return FirebaseResponse(
                user_id=firebase["localId"],
                email=firebase["email"],
                id_token=firebase["idToken"],
                refresh_token=firebase["refreshToken"],
                expires_in=firebase["expiresIn"],
            )
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def reset_password_email(self, email: str) -> dict:
        """This will request a password reset by sending an email to the user.

        Args:
            email (str): User's email that wants to reset password.

        Returns:
            dict: Object built from API response.
        """
        try:
            reset_password_email = ResetPasswordEmail(email=email)
            firebase = self.firebase_call(
                payload=reset_password_email.payload(), option="sendOobCode"
            )
            return FirebaseResponse(email=firebase["email"], date=datetime.now())
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def verify_reset_code(self, oob_code: str) -> dict:
        """This will verify the oob code from Firebase. The user will receive an email containing this code.

        Args:
            oob_code (str): oob code from email.

        Returns:
            dict: Object build from the API response.
        """
        try:
            check_oob_code = CheckOobCode(oob_code=oob_code)
            firebase = self.firebase_call(
                payload=check_oob_code.payload(), option="resetPassword"
            )
            return FirebaseResponse(email=firebase["email"], date=datetime.now())
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def reset_password(
        self, oob_code: str, password: str, password_confirm: str
    ) -> dict:
        """Once the oobcode has been verified, we can reset the password with this method.

        Args:
            oob_code (str): oob code received in the email.
            password (str): User's NEW password.
            password_confirm (str): User's NEW password confirmation.

        Returns:
            dict: Object built from API response.
        """
        try:
            reset_password = ResetPassword(
                oob_code=oob_code, password=password, password_confirm=password_confirm
            )
            firebase = self.firebase_call(
                payload=reset_password.payload(), option="resetPassword"
            )
            return FirebaseResponse(email=firebase["email"], date=datetime.now())
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def change_email(self, id_token: str, email: str) -> dict:
        """Method will change the email of a user.

        Args:
            id_token (str): This will be inside the login object. Usually expires within 3600 seconds.
            email (str): User's NEW email address.

        Returns:
            dict: Object build from API response.
        """
        try:
            change_email = ChangeEmail(id_token=id_token, email=email)
            firebase = self.firebase_call(
                payload=change_email.payload(), option="update"
            )
            return FirebaseResponse(
                email=firebase["email"],
                user_id=firebase["localId"],
                id_token=firebase["idToken"],
                refresh_token=firebase["refreshToken"],
            )
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def send_email_verification(self, id_token: str) -> dict:
        """Verify a user's email address.

        Args:
            id_token (str): This will be inside the login object. Usually expires within 3600 seconds.

        Returns:
            dict: Object build from API response.
        """
        try:
            send_email_verification = SendEmailVerification(id_token=id_token)
            firebase = self.firebase_call(
                payload=send_email_verification.payload(), option="sendOobCode"
            )
            return FirebaseResponse(email=firebase["email"], date=datetime.now())
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def confirm_email_verification(self, oob_code: str) -> dict:
        """User will receive an email address containing the oob code.

        Args:
            oob_code (str): code from inside email.

        Returns:
            dict: Object build from API response.
        """
        try:
            confirm_email_verification = ConfirmEmailVerification(oob_code=oob_code)
            firebase = self.firebase_call(
                payload=confirm_email_verification.payload(), option="update"
            )
            return FirebaseResponse(
                email=firebase["email"],
                email_verified=firebase["emailVerified"],
            )
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def delete_account(self, id_token: str) -> dict:
        """Delete a user's account.

        Args:
            id_token (str): Token from login object.

        Returns:
            dict: Object build from API response.
        """
        try:
            delete_account = DeleteAccount(id_token=id_token)
            firebase = self.firebase_call(
                payload=delete_account.payload(), option="delete"
            )
            return self.return_message(status="success", message="Account deleted")
        except ValueError as e:
            return self.return_message(status="error", message=e)

    def change_password(
        self, id_token: str, password: str, password_confirm: str
    ) -> dict:
        """Change a user's password WITHOUT receiving oob code via email. Alternate password reset method.

        Args:
            id_token (str): Token obtained from login method. (login.id_token)
            password (str): User's NEW password.
            password_confirm (str): User's NEW confirmation password.

        Returns:
            dict: _description_
        """
        try:
            change_password = ChangePassword(
                id_token=id_token, password=password, password_confirm=password_confirm
            )
            firebase = self.firebase_call(
                payload=change_password.payload(), option="update"
            )
            return FirebaseResponse(
                email=firebase["email"],
                user_id=firebase["localId"],
                id_token=firebase["idToken"],
                refresh_token=firebase["refreshToken"],
            )
        except ValueError as e:
            return self.return_message(status="error", message=e)
