import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

class GeminiHandler:
    def __init__(self):
        load_dotenv()
        api_key = os.getenv('GEMINI_API_KEY')
        self.client = genai.Client(api_key=api_key)

    def query(self, system_prompt, prompt):
        response = self.client.models.generate_content(
            model="gemini-2.0-flash",
            config=types.GenerateContentConfig(
                system_instruction=system_prompt),
            contents=prompt
        )

        return response.candidates[0].content.parts[0].text

