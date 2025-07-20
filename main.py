import streamlit as st

from email_categorizer import EmailCategorizer
from gmail_processor import GmailProcessor

# Configure the page
st.set_page_config(
    page_title="Gmail Email Categorizer",
    page_icon="📧",
    layout="wide"
)


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
                    categorizer = EmailCategorizer("")

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