import unittest
from unittest.mock import patch

from auth import Auth 

from utils import FirebaseResponse

class FirebaseAuthTests(unittest.TestCase):
    
        
    @patch('auth.Auth.firebase_call')
    def test_login(self, mock_firebase_call):
        auth = Auth('a123456789')
        self.data = {
            "message": {
                "status": "success",
                "result": "Logged in successfully."},
            "localId": "123456789",
            "email": "jane@doe.net",
            "idToken": "123456789",
            "refreshToken": "123456789",
            "expiresIn": "3600"
        }
        
        mock_firebase_call.return_value = self.data

        obj = FirebaseResponse(
            email=self.data['email'],
            message=self.data['message'],
            user_id=self.data['localId'],
            id_token=self.data['idToken'],
            refresh_token=self.data['refreshToken'],
            expires_in=self.data['expiresIn']
        )

        self.assertEqual(auth.login('jane@doe.net', 'abc123456789').dict(), obj.dict())

if __name__ == "__main__":
    unittest.main()