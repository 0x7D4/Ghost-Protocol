# Deceptive Personas for Ghost-Protocol

This directory contains the system prompts for the LLM-driven persona engine.

## Production Requirements

To use these personas in production, ensure:
1.  **Ollama** is running locally (default: `http://127.0.0.1:11434`).
2.  The **phi3:mini** model is pre-loaded: `ollama run phi3:mini`.

## Structure

Each `.toml` file corresponds to a specific service identified by its default port or mapping in `ghostd`.
