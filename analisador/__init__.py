"""Analisador de logs: detecta força bruta, varreduras e tentativas de injeção."""

from .deteccao import analisar_linhas, Relatorio

__all__ = ["analisar_linhas", "Relatorio"]
__version__ = "1.0.0"
