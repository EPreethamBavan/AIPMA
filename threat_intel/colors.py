"""
Color utilities for terminal output
Simplified version for GUI integration
"""


class ForegroundColors:
    """Foreground colors"""

    def __init__(self):
        # Light background colors
        self.lightred = "\033[91m"
        self.lightgreen = "\033[92m"
        self.lightyellow = "\033[93m"
        self.lightblue = "\033[94m"
        self.lightcyan = "\033[96m"
        self.yellow = "\033[33m"
        self.green = "\033[32m"
        self.red = "\033[31m"
        self.cyan = "\033[36m"
        self.blue = "\033[34m"
        self.purple = "\033[35m"
        self.pink = "\033[95m"
        self.orange = "\033[38;5;208m"

    def error(self, bkg):
        return self.lightred if bkg == 1 else self.red

    def info(self, bkg):
        return self.lightcyan if bkg == 1 else self.cyan


class MyColors:
    """Color management class"""

    def __init__(self):
        self.foreground = ForegroundColors()
        self.reset = "\033[0m"


# Global instance
mycolors = MyColors()


def printr():
    """Print a separator line"""
    print("\n" + "-" * 100)


def printc(text, color):
    """Print colored text"""
    print(f"{color}{text}{mycolors.reset}")
