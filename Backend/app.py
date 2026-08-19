from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyze_text, evaluate_answer

app = Flask(__name__)
CORS(app)

@app.route("/question", methods=["GET"])
def question():
    return jsonify({
        "question": "Explain polymorphism in OOP with an example."
    })

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    text = data.get("text", "")

    score = analyze_text(text)
    evaluation = evaluate_answer(text)

    return jsonify({
        "truth_score": score,
        "confidence": "High" if score > 70 else "Low",
        "stress": "High" if score < 40 else "Normal",
        "ai_feedback": "Answer is clear and confident" if score > 70 else "Improve clarity and reduce fillers",
        "evaluation": evaluation
    })

if __name__ == "__main__":
    app.run(debug=True)