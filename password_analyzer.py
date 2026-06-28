

import re
import string




COMMON_PASSWORDS: set[str] = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "monkey", "1234567890", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess", "welcome",
    "shadow", "superman", "michael", "football", "password1", "letmein",
    "admin", "login", "hello", "master", "solo", "starwars", "access",
    "batman", "passw0rd", "654321", "666666", "987654321", "1q2w3e4r",
    "qwerty123", "qwertyuiop", "mypassword", "monkey123", "test1234",
    "password123", "admin123", "root", "toor", "pass", "guest",
    "changeme", "secret", "love", "god", "nothing", "jessica", "andrew",
    "daniel", "jordan", "harley", "ranger", "hunter", "thomas", "robert",
    "hockey", "killer", "george", "charlie", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111",
    "131313", "000000", "222222", "9999999", "7777777", "1111111",
    "aa123456", "donald", "naruto", "pokemon", "asdfgh", "123qwe",
    "asdf", "zxcv", "1234", "0000", "pass1", "test", "temp", "user",
    "default", "qwert", "abc", "winter2023", "summer2023", "spring2024",
    "fall2023", "winter2024", "password2024", "password2023",
    # Add more as needed — this set grows at O(1) lookup cost regardless
}



class CheckResult:
    """Represents the result of one password strength check."""

    def __init__(self, name: str, passed: bool, points: int, suggestion: str = ""):
        self.name = name
        self.passed = passed
        self.points = points          # points awarded if passed
        self.suggestion = suggestion  # shown only when failed

    def __repr__(self) -> str:
        status = "✅" if self.passed else "❌"
        return f"{status}  {self.name}"




class PasswordAnalyzer:
   
    POINTS = {
        "length_min":    20,   # ≥ 8 chars
        "length_good":   10,   # ≥ 12 chars (bonus on top of min)
        "length_strong":  5,   # ≥ 16 chars (bonus on top of good)
        "uppercase":     15,
        "lowercase":     15,
        "digit":         20,
        "symbol":        20,
    }

    STRENGTH_LABELS = {
        range(0,  40): ("Weak",      "🔴"),
        range(40, 60): ("Fair",      "🟠"),
        range(60, 80): ("Good",      "🟡"),
        range(80, 95): ("Strong",    "🟢"),
        range(95,101): ("Very Strong","🟢"),
    }

    def __init__(self, password: str):
        self.password = password
        self.results: list[CheckResult] = []
        self.score: int = 0
        self._analyze()

   

    def _has_uppercase(self) -> bool:
        return any(c.isupper() for c in self.password)

    def _has_lowercase(self) -> bool:
        return any(c.islower() for c in self.password)

    def _has_digit(self) -> bool:
        return any(c.isdigit() for c in self.password)

    def _has_symbol(self) -> bool:
        return any(c in string.punctuation for c in self.password)

    def _is_common(self) -> bool:
        return self.password.lower() in COMMON_PASSWORDS

    

    def _analyze(self) -> None:
        p = self.password
        length = len(p)

        # 1. Minimum length
        min_ok = length >= 8
        self.results.append(CheckResult(
            name="At least 8 characters",
            passed=min_ok,
            points=self.POINTS["length_min"],
            suggestion="Use at least 8 characters.",
        ))

        
        good_ok = length >= 12
        self.results.append(CheckResult(
            name="At least 12 characters (recommended)",
            passed=good_ok,
            points=self.POINTS["length_good"],
            suggestion="Aim for 12+ characters for better security.",
        ))

        
        strong_ok = length >= 16
        self.results.append(CheckResult(
            name="At least 16 characters (strong)",
            passed=strong_ok,
            points=self.POINTS["length_strong"],
            suggestion="16+ characters makes brute-force attacks impractical.",
        ))

        
        up_ok = self._has_uppercase()
        self.results.append(CheckResult(
            name="Contains uppercase letter (A–Z)",
            passed=up_ok,
            points=self.POINTS["uppercase"],
            suggestion="Add at least one uppercase letter (e.g. A, B, C…).",
        ))

       
        lo_ok = self._has_lowercase()
        self.results.append(CheckResult(
            name="Contains lowercase letter (a–z)",
            passed=lo_ok,
            points=self.POINTS["lowercase"],
            suggestion="Add at least one lowercase letter (e.g. a, b, c…).",
        ))

        
        dig_ok = self._has_digit()
        self.results.append(CheckResult(
            name="Contains a number (0–9)",
            passed=dig_ok,
            points=self.POINTS["digit"],
            suggestion="Include at least one digit (0–9).",
        ))

       
        sym_ok = self._has_symbol()
        self.results.append(CheckResult(
            name="Contains a symbol (!@#$…)",
            passed=sym_ok,
            points=self.POINTS["symbol"],
            suggestion="Add a special character like !, @, #, $, %, ^, &, *.",
        ))

       
        self.score = sum(r.points for r in self.results if r.passed)
        self.score = min(self.score, 100)

       
        self.is_common = self._is_common()
        if self.is_common:
            self.score = min(self.score, 10)  # cap at 10 if it's a known password

    

    def get_strength_label(self) -> tuple[str, str]:
        """Returns (label, emoji) for the current score."""
        for score_range, label in self.STRENGTH_LABELS.items():
            if self.score in score_range:
                return label
        return ("Unknown", "⚪")

    def get_suggestions(self) -> list[str]:
        """Returns a list of actionable improvement suggestions."""
        suggestions = [r.suggestion for r in self.results if not r.passed and r.suggestion]
        if self.is_common:
            suggestions.insert(0, "⚠️  This is a commonly used password — change it immediately.")
        return suggestions

    def get_score_bar(self, width: int = 30) -> str:
        """Returns an ASCII progress bar for the score."""
        filled = int((self.score / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {self.score}/100"



class ReportPrinter:
    """Formats and prints the analysis report to stdout."""

    WIDTH = 52

    def print_report(self, analyzer: PasswordAnalyzer) -> None:
        label, emoji = analyzer.get_strength_label()
        suggestions = analyzer.get_suggestions()

        self._divider()
        print(f"{'PASSWORD STRENGTH REPORT':^{self.WIDTH}}")
        self._divider()

        # Individual checks
        print("\n  CHECKS")
        print("  " + "─" * 44)
        for result in analyzer.results:
            print(f"  {result}")

        # Common password warning
        if analyzer.is_common:
            print(f"\n  ⛔  COMMON PASSWORD DETECTED — score capped")

        # Score bar
        print(f"\n  SCORE")
        print(f"  {analyzer.get_score_bar()}")
        print(f"  Strength: {emoji}  {label}")

        # Suggestions
        if suggestions:
            print(f"\n  SUGGESTIONS TO IMPROVE")
            print("  " + "─" * 44)
            for i, s in enumerate(suggestions, 1):
                print(f"  {i}. {s}")
        else:
            print(f"\n  🎉  Great password! No improvements needed.")

        self._divider()

    def _divider(self) -> None:
        print("=" * self.WIDTH)




def main() -> None:
    printer = ReportPrinter()

    print("\n╔══════════════════════════════════════════════════╗")
    print("║         🔐 PASSWORD STRENGTH ANALYZER            ║")
    print("╚══════════════════════════════════════════════════╝")
    print("  Type 'quit' to exit.\n")

    while True:
        password = input("  Enter password: ")

        if password.lower() == "quit":
            print("\n  Goodbye! Stay safe online. 👋\n")
            break

        if not password:
            print("  [!] Please enter a password.\n")
            continue

        analyzer = PasswordAnalyzer(password)
        print()
        printer.print_report(analyzer)
        print()


if __name__ == "__main__":
    main()
