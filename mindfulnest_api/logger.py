"""
Simple logging configuration for MindfulNest API.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional


def setup_logger(name: str = "mindfulnest", level: int = logging.INFO) -> logging.Logger:
    """
    Set up a simple logger that writes to both file and console.

    Args:
        name: Logger name.
        level: Logging level (e.g. logging.INFO, logging.DEBUG).

    Returns:
        Configured `logging.Logger` instance.
    """
    logger = logging.getLogger(name)

    # Avoid reconfiguring an existing logger
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # File handler - logs everything to file
    log_file = log_dir / f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Console handler - only important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Simple format
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
