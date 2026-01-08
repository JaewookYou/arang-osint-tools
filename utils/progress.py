"""
Red Iris Info Gather - Progress Spinner Utility

Provides animated console progress indicators:
- Spinning progress ring
- Hierarchical task display
- Status updates with timing
"""
import sys
import time
import threading
from typing import Optional
from datetime import datetime


class Spinner:
    """Animated spinner for console output"""
    
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    CLEAR_LINE = "\033[2K"  # ANSI escape to clear entire line
    
    def __init__(self, message: str = "", indent: int = 0):
        self.message = message
        self.indent = indent
        self.running = False
        self.thread = None
        self.frame_idx = 0
        self.start_time = None
    
    def _spin(self):
        while self.running:
            frame = self.FRAMES[self.frame_idx % len(self.FRAMES)]
            indent_str = "    " * self.indent
            elapsed = time.time() - self.start_time
            # Clear line and write spinner
            sys.stdout.write(f"\r{self.CLEAR_LINE}\r{indent_str}{frame} {self.message} ({elapsed:.1f}s)")
            sys.stdout.flush()
            self.frame_idx += 1
            time.sleep(0.1)
    
    def start(self):
        self.running = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()
    
    def stop(self, success: bool = True, message: str = None):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        indent_str = "    " * self.indent
        status = "✓" if success else "✗"
        color = "\033[92m" if success else "\033[91m"  # Green or Red
        reset = "\033[0m"
        
        final_message = message if message else self.message
        # Clear line and write final status
        sys.stdout.write(f"\r{self.CLEAR_LINE}\r{indent_str}{color}{status}{reset} {final_message} ({elapsed:.1f}s)\n")
        sys.stdout.flush()
    
    def update(self, message: str):
        self.message = message


class ProgressLogger:
    """
    Hierarchical progress logger with spinners.
    
    Usage:
        logger = ProgressLogger()
        
        # Major section
        logger.section("🔍 서브도메인 스캔")
        
        # Sub-task with spinner
        with logger.task("subfinder 실행"):
            # ... do work ...
            pass
        
        # Simple status
        logger.status("발견: 15개 서브도메인")
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.current_spinner: Optional[Spinner] = None
        self.indent_level = 0
    
    def section(self, title: str):
        """Print major section header"""
        print()
        print(f"{'─' * 60}")
        print(f"  {title}")
        print(f"{'─' * 60}")
        self.indent_level = 1
    
    def task(self, message: str):
        """Context manager for a task with spinner"""
        return TaskContext(self, message)
    
    def status(self, message: str, level: str = "info"):
        """Print status message"""
        indent = "    " * self.indent_level
        symbols = {
            "info": "ℹ️ ",
            "success": "✅",
            "warning": "⚠️ ",
            "error": "❌",
            "result": "📊"
        }
        symbol = symbols.get(level, "•")
        print(f"{indent}{symbol} {message}")
    
    def substep(self, message: str):
        """Print substep (indented)"""
        indent = "    " * (self.indent_level + 1)
        print(f"{indent}└─ {message}")
    
    def result(self, label: str, value):
        """Print result with label"""
        indent = "    " * self.indent_level
        print(f"{indent}   {label}: {value}")


class TaskContext:
    """Context manager for task with spinner"""
    
    def __init__(self, logger: ProgressLogger, message: str):
        self.logger = logger
        self.message = message
        self.spinner = Spinner(message, indent=logger.indent_level)
        self.success = True
        self.final_message = None
    
    def __enter__(self):
        self.spinner.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.success = False
            self.final_message = f"{self.message} - 실패"
        self.spinner.stop(self.success, self.final_message)
        return False  # Don't suppress exceptions
    
    def update(self, message: str):
        """Update spinner message"""
        self.spinner.update(message)
        self.final_message = message
    
    def complete(self, message: str):
        """Set completion message"""
        self.final_message = message


# Global logger instance
_logger: Optional[ProgressLogger] = None


def get_logger() -> ProgressLogger:
    """Get or create global progress logger"""
    global _logger
    if _logger is None:
        _logger = ProgressLogger()
    return _logger


def set_verbose(verbose: bool):
    """Set verbose mode for logger"""
    get_logger().verbose = verbose


# Convenience functions
def section(title: str):
    """Print section header"""
    get_logger().section(title)


def task(message: str) -> TaskContext:
    """Start task with spinner"""
    return get_logger().task(message)


def status(message: str, level: str = "info"):
    """Print status message"""
    get_logger().status(message, level)


def substep(message: str):
    """Print substep"""
    get_logger().substep(message)


def result(label: str, value):
    """Print result"""
    get_logger().result(label, value)
