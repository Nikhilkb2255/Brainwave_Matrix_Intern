import re
import math
from nltk.corpus import words
import nltk

try:
    nltk.data.find('corpora/words.zip')
except LookupError:
    nltk.download('words')

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = {"password", "123456", "12345678", "qwerty", "letmein", "welcome", "1234", "admin"}
        self.dictionary_words = set(words.words())

    def calculate_entropy(self, password):
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'[0-9]', password):
            pool_size += 10
        if re.search(r'[\W_]', password):
            pool_size += 32  
        entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
        return entropy

    def evaluate_password(self, password):
        score = 0
        feedback = []

        # Length Check 
        if len(password) < 8:
            feedback.append("Password is too short (less than 8 characters). Consider using 12+ characters for better security.")
        elif len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        # Character Diversity Check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters to increase strength.")

        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters to increase strength.")

        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers to increase strength.")

        if re.search(r'[\W_]', password):
            score += 1
        else:
            feedback.append("Add special characters (e.g., @, #, $, etc.) to increase strength.")

        # Sequential Patterns Check
        if re.search(r'(.)\1\1', password):
            feedback.append("Avoid repeating characters three or more times in a row.")
        if re.search(r'(123|234|345|456|567|678|789|890|012)', password):
            feedback.append("Avoid sequential numbers (e.g., 123, 456).")
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm)', password, re.IGNORECASE):
            feedback.append("Avoid sequential letters (e.g., abc, xyz).")

        # Common Password Check
        if password.lower() in self.common_passwords:
            feedback.append("This password is very common. Choose a more unique password.")

        # Dictionary Word Check
        for word in self.dictionary_words:
            if word in password.lower() and len(word) > 3:
                feedback.append("Avoid using dictionary words in your password.")
                break

        # Entropy Calculation
        entropy = self.calculate_entropy(password)
        if entropy < 28:
            feedback.append("Password entropy is very low. Consider adding more character types.")
        elif entropy < 50:
            feedback.append("Password entropy is moderate. Adding length and complexity can improve it.")
        else:
            score += 1  

        # Calculate Strength
        if score >= 7:
            strength = "Very Strong"
        elif score == 6:
            strength = "Strong"
        elif score == 5:
            strength = "Moderate"
        elif score == 4:
            strength = "Weak"
        else:
            strength = "Very Weak"

        return {
            "strength": strength,
            "score": score,
            "entropy": entropy,
            "feedback": feedback
        }

if __name__ == "__main__":
    checker = PasswordStrengthChecker()
    password = input("Enter a password to check its strength: ")
    result = checker.evaluate_password(password)

    print(f"\nPassword Strength: {result['strength']}")
    print(f"Score: {result['score']} / 8")
    print(f"Entropy: {result['entropy']:.2f} bits")
    if result['feedback']:
        print("Feedback for improving strength:")
        for suggestion in result['feedback']:
            print(f" - {suggestion}")
