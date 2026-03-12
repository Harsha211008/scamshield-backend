from langdetect import detect

translations={
"te":{
"SAFE":"సురక్షితం",
"PROMO":"ప్రచారం",
"SUSPICIOUS":"సందేహాస్పదం",
"SCAM":"మోసం"
},
"hi":{
"SAFE":"सुरक्षित",
"PROMO":"प्रमोशन",
"SUSPICIOUS":"संदिग्ध",
"SCAM":"धोखा"
}
}

def detect_language(text):

    try:
        return detect(text)
    except:
        return "en"

def translate_category(category,lang):

    if lang in translations:
        return translations[lang].get(category,category)

    return category