import re

def analyze_text(text):
    text = text.lower()
    filler_words = ["um", "uh", "like", "basically", "actually"]
    words = re.findall(r"\b\w+\b", text)

    filler_count = sum(1 for w in words if w in filler_words)
    score = max(0, 100 - filler_count * 10)

    return score


def evaluate_answer(text):
    text_lower = text.lower()
    words = re.findall(r"\b\w+\b", text_lower)
    word_count = len(words)

    filler_words = ["um", "uh", "like", "basically", "actually"]
    filler_count = sum(1 for w in words if w in filler_words)

    technical_keywords = [
        "class", "object", "inheritance", "polymorphism", "encapsulation",
        "abstraction", "method", "function", "data", "algorithm",
        "example", "program", "memory", "database"
    ]

    keyword_count = sum(1 for word in technical_keywords if word in text_lower)

    technical_accuracy = min(100, keyword_count * 15 + min(word_count, 40))
    communication = max(0, 100 - filler_count * 12)

    if word_count >= 25:
        confidence = 85
    elif word_count >= 12:
        confidence = 65
    else:
        confidence = 40

    suggestions = []

    if word_count < 20:
        suggestions.append("Give a more detailed answer.")
    if filler_count > 3:
        suggestions.append("Reduce filler words.")
    if keyword_count < 2:
        suggestions.append("Add more technical keywords.")
    if "example" not in text_lower:
        suggestions.append("Add one real example.")

    if not suggestions:
        suggestions.append("Good answer. Keep practicing with confidence.")

    return {
        "technical_accuracy": technical_accuracy,
        "communication": communication,
        "confidence_score": confidence,
        "suggestions": suggestions
    }