import streamlit as st
import json
import base64
from datetime import datetime, timedelta
from typing import List, Dict, Any
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Gmail API Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailProcessor:
    def __init__(self):
        self.flow = None
        self.creds_info = None
        self.service = None
        self.credentials = None

    def authenticate_gmail(self, credentials_json: str) -> bool:
        """Authenticate with Gmail API using uploaded credentials"""
        try:
            # Parse the credentials JSON
            creds_info = json.loads(credentials_json)

            # Check if this is a service account or OAuth credentials
            if creds_info.get('type') == 'service_account':
                st.error("Service account credentials don't work for Gmail API. Please use OAuth 2.0 credentials.")
                return False

            # Store credentials info for later use
            self.creds_info = creds_info

            # Use the out-of-band (OOB) redirect URI for desktop apps
            redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'

            # Create flow from client config
            self.flow = Flow.from_client_config(
                creds_info,
                scopes=SCOPES,
                redirect_uri=redirect_uri
            )

            # Get authorization URL
            auth_url, _ = self.flow.authorization_url(
                prompt='consent',
                access_type='offline'
            )

            st.markdown("### Step 1: Authorize the application")
            st.markdown(f"**[Click here to authorize]({auth_url})**")
            st.markdown(
                "After authorization, you'll see a page with an authorization code. Copy that code and paste it below.")

            return "auth_url_generated"

        except Exception as e:
            st.error(f"Authentication setup failed: {str(e)}")
            return False

    def verify_auth_code(self, auth_code: str) -> bool:
        """Verify the authorization code and complete authentication"""
        try:
            if not hasattr(self, 'flow') or not self.flow:
                st.error("Authentication flow not initialized. Please upload credentials first.")
                return False

            # Clean the authorization code (remove any whitespace)
            auth_code = auth_code.strip()

            # Exchange authorization code for credentials
            self.flow.fetch_token(code=auth_code)
            self.credentials = self.flow.credentials

            # Build the Gmail service
            self.service = build('gmail', 'v1', credentials=self.credentials)

            # Test the connection
            profile = self.service.users().getProfile(userId='me').execute()
            st.success(f"Successfully authenticated! Email: {profile.get('emailAddress', 'Unknown')}")
            return True

        except Exception as e:
            st.error(f"Authentication failed: {str(e)}")
            st.error("Please make sure:")
            st.error("1. You copied the complete authorization code")
            st.error("2. You're added as a test user in Google Cloud Console")
            st.error("3. The authorization code hasn't expired")
            return False

    def get_todays_emails(self) -> List[Dict[str, Any]]:
        """Retrieve emails from the last 24 hours"""
        try:
            # Calculate date 24 hours ago
            yesterday = datetime.now() - timedelta(days=1)
            query = f'after:{yesterday.strftime("%Y/%m/%d")}'

            # Search for emails
            results = self.service.users().messages().list(
                userId='me', q=query, maxResults=100
            ).execute()

            messages = results.get('messages', [])
            emails = []

            for message in messages:
                # Get full message details
                msg = self.service.users().messages().get(
                    userId='me', id=message['id'], format='full'
                ).execute()

                # Extract email details
                email_data = self.extract_email_data(msg)
                emails.append(email_data)

            return emails

        except HttpError as error:
            st.error(f'An error occurred: {error}')
            return []

    def extract_email_data(self, message: Dict) -> Dict[str, Any]:
        """Extract relevant data from Gmail message"""
        payload = message['payload']
        headers = payload.get('headers', [])

        # Extract headers
        email_data = {
            'id': message['id'],
            'threadId': message['threadId'],
            'subject': '',
            'sender': '',
            'date': '',
            'body': '',
            'gmail_url': f"https://mail.google.com/mail/u/0/#inbox/{message['id']}"
        }

        for header in headers:
            name = header.get('name', '').lower()
            value = header.get('value', '')

            if name == 'subject':
                email_data['subject'] = value
            elif name == 'from':
                email_data['sender'] = value
            elif name == 'date':
                email_data['date'] = value

        # Extract body
        email_data['body'] = self.extract_body(payload)

        return email_data

    def extract_body(self, payload: Dict) -> str:
        """Extract email body from payload"""
        body = ""

        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data', '')
                    if data:
                        body = base64.urlsafe_b64decode(data).decode('utf-8')
                        break
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body'].get('data', '')
                if data:
                    body = base64.urlsafe_b64decode(data).decode('utf-8')

        return body

