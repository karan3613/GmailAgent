import streamlit as st
import json
import base64
from datetime import datetime, timedelta
import re
from typing import List, Dict, Any
import pickle
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.generativeai as genai
from io import StringIO

# Configure the page
st.set_page_config(
    page_title="Gmail Email Categorizer",
    page_icon="📧",
    layout="wide"
)

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


class EmailCategorizer:
    def __init__(self, gemini_api_key: str = None):
        self.gemini_api_key = gemini_api_key
        if gemini_api_key:
            genai.configure(api_key=gemini_api_key)
            self.model = genai.GenerativeModel('gemini-pro')

    def categorize_email(self, email: Dict[str, Any], prompts: List[str]) -> int:
        """
        Categorize email based on prompts.
        Returns: 0, 1, 2 for prompt categories, or -1 if no match
        """
        email_content = f"""
        Subject: {email['subject']}
        From: {email['sender']}
        Body: {email['body'][:500]}...
        """

        # Simple keyword-based categorization (fallback method)
        if not self.gemini_api_key:
            return self.simple_categorize(email_content, prompts)

        # Use Gemini for better categorization
        try:
            prompt = f"""
            You are an email categorization assistant. Given an email and three category descriptions, determine which category (0, 1, or 2) the email belongs to. If it doesn't fit any category, return -1.

            Email content:
            {email_content}

            Categories:
            0: {prompts[0]}
            1: {prompts[1]}
            2: {prompts[2]}

            Return only the category number (0, 1, 2, or -1). No explanation needed.
            """

            response = self.model.generate_content(prompt)
            result = response.text.strip()

            try:
                category = int(result)
                return category if category in [0, 1, 2, -1] else -1
            except ValueError:
                return -1

        except Exception as e:
            st.warning(f"Gemini categorization failed, using simple method: {str(e)}")
            return self.simple_categorize(email_content, prompts)

    def simple_categorize(self, email_content: str, prompts: List[str]) -> int:
        """Simple keyword-based categorization"""
        email_content_lower = email_content.lower()

        for i, prompt in enumerate(prompts):
            prompt_keywords = prompt.lower().split()
            matches = sum(1 for keyword in prompt_keywords if keyword in email_content_lower)

            if matches >= max(1, len(prompt_keywords) // 3):  # At least 1/3 of keywords match
                return i

        return -1


def main():
    st.title("📧 Gmail Email Categorizer")
    st.markdown("Upload your Gmail API credentials and categorize your emails based on custom prompts!")

    # Initialize session state
    if 'gmail_processor' not in st.session_state:
        st.session_state.gmail_processor = GmailProcessor()

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    if 'verified' not in st.session_state:
        st.session_state.verified = False

    if 'emails' not in st.session_state:
        st.session_state.emails = []

    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")

        # Gmail API Credentials Upload
        st.subheader("1. Gmail API Setup")
        uploaded_file = st.file_uploader(
            "Upload Gmail API Credentials (JSON)",
            type=['json'],
            help="Download credentials.json from Google Cloud Console"
        )

        if uploaded_file and not st.session_state.authenticated:
            credentials_json = uploaded_file.read().decode('utf-8')
            if st.button("Authenticate Gmail"):
                st.session_state.authenticated = st.session_state.gmail_processor.authenticate_gmail(credentials_json)

        if st.session_state.authenticated:
            auth_code = st.text_input("Enter the auth code")
            if st.button("Verify Code"):
                st.session_state.verified = st.session_state.gmail_processor.verify_auth_code(auth_code)


    # Main content area
    if st.session_state.authenticated and st.session_state.verified:
        st.success("✅ Gmail authenticated successfully!")

        # Email categorization prompts
        st.subheader("Email Category Prompts")
        col1, col2, col3 = st.columns(3)

        with col1:
            prompt1 = st.text_area("Category 1 Description",
                                   placeholder="e.g., Work-related emails, project updates, meetings")

        with col2:
            prompt2 = st.text_area("Category 2 Description",
                                   placeholder="e.g., Personal emails, family, friends")

        with col3:
            prompt3 = st.text_area("Category 3 Description",
                                   placeholder="e.g., Shopping, promotions, newsletters")

        # Fetch and categorize emails
        if st.button("📥 Fetch & Categorize Emails", type="primary"):
            if not all([prompt1, prompt2, prompt3]):
                st.error("Please provide all three category descriptions.")
            else:
                with st.spinner("Fetching emails from last 24 hours..."):
                    emails = st.session_state.gmail_processor.get_todays_emails()
                    st.session_state.emails = emails

                if emails:
                    st.success(f"Found {len(emails)} emails from the last 24 hours.")

                    # Initialize categorizer
                    categorizer = EmailCategorizer("AIzaSyAeu5xUWvnXP3PtpE6t70psSD9WvvV2Y_g")

                    # Categorize emails
                    categorized_emails = {0: [], 1: [], 2: [], -1: []}

                    with st.spinner("Categorizing emails..."):
                        for email in emails:
                            category = categorizer.categorize_email(email, [prompt1, prompt2, prompt3])
                            categorized_emails[category].append(email)

                    # Display results
                    st.subheader("📊 Categorization Results")

                    # Category tabs
                    tab1, tab2, tab3, tab4 = st.tabs([
                        f"Category 1 ({len(categorized_emails[0])})",
                        f"Category 2 ({len(categorized_emails[1])})",
                        f"Category 3 ({len(categorized_emails[2])})",
                        f"Uncategorized ({len(categorized_emails[-1])})"
                    ])

                    # Display emails for each category
                    categories = [
                        (tab1, 0, prompt1, "🔵"),
                        (tab2, 1, prompt2, "🟢"),
                        (tab3, 2, prompt3, "🟡"),
                        (tab4, -1, "Uncategorized", "⚪")
                    ]

                    for tab, cat_id, cat_name, emoji in categories:
                        with tab:
                            st.markdown(f"### {emoji} {cat_name}")

                            if categorized_emails[cat_id]:
                                for i, email in enumerate(categorized_emails[cat_id]):
                                    with st.expander(f"📧 {email['subject'][:50]}... - {email['sender']}"):
                                        col1, col2 = st.columns([3, 1])

                                        with col1:
                                            st.write(f"**From:** {email['sender']}")
                                            st.write(f"**Date:** {email['date']}")
                                            st.write(f"**Subject:** {email['subject']}")
                                            if email['body']:
                                                st.write(f"**Preview:** {email['body'][:200]}...")

                                        with col2:
                                            st.link_button(
                                                "📧 Open in Gmail",
                                                email['gmail_url'],
                                                use_container_width=True
                                            )
                            else:
                                st.info("No emails found in this category.")
                else:
                    st.warning("No emails found in the last 24 hours.")

    else:
        st.info("👆 Please upload your Gmail API credentials and authenticate to get started.")

        # Instructions
        with st.expander("📋 Setup Instructions"):
            st.markdown("""
            ### How to set up Gmail API:

            1. **Go to Google Cloud Console**: Visit [console.cloud.google.com](https://console.cloud.google.com)
            2. **Create a new project** or select an existing one
            3. **Enable Gmail API**:
               - Go to "APIs & Services" > "Library"
               - Search for "Gmail API" and enable it
            4. **Configure OAuth consent screen**:
               - Go to "APIs & Services" > "OAuth consent screen"
               - Choose "External" user type
               - Fill in required fields (App name, User support email, etc.)
               - **IMPORTANT**: Add your Gmail address in "Test users" section
            5. **Create credentials**:
               - Go to "APIs & Services" > "Credentials"
               - Click "Create Credentials" > "OAuth 2.0 Client IDs"
               - Choose "Desktop application"
               - Download the JSON file
            6. **Upload the JSON file** using the file uploader above

            ### Troubleshooting "Error 403: access_denied":
            - Make sure you added your Gmail address as a test user
            - Ensure OAuth consent screen is properly configured
            - Use the same Gmail account for testing that you added as test user

            ### Optional: Gemini API Key
            - For better email categorization, provide your Gemini API key
            - Get it from [Google AI Studio](https://makersuite.google.com/app/apikey)
            - Without it, the app uses keyword-based matching (less accurate)
            """)


if __name__ == "__main__":
    main()