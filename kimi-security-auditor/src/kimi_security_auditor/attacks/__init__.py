"""
Attack modules for detecting various vulnerabilities.
"""

from .nosql_injection import NoSQLInjectionScanner
from .ssti import SSTIScanner
from .xxe import XXEScanner
from .cors import CORSChecker
from .security_headers import SecurityHeadersAnalyzer
from .directory_traversal import DirectoryTraversalScanner
from .file_upload import FileUploadScanner
from .sql_injection import SQLInjectionScanner
from .command_injection import CommandInjectionScanner
from .jwt_scanner import JWTScanner

__all__ = [
    "NoSQLInjectionScanner",
    "SSTIScanner", 
    "XXEScanner",
    "CORSChecker",
    "SecurityHeadersAnalyzer",
    "DirectoryTraversalScanner",
    "FileUploadScanner",
    "SQLInjectionScanner",
    "CommandInjectionScanner",
    "JWTScanner",
]
