import streamlit as st
from typing import List, Dict, Any
import google.generativeai as genai
from io import StringIO

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

