from langdetect import detect

class LanguageManager:

    def process(self,text):

        try:
            lang=detect(text)
        except:
            lang="unknown"

        return {
            "language":lang,
            "translated_text":text
        }