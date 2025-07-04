# AI Assistant for IDA Pro

AI Assistant simplifies routine reverse engineering tasks. The plugin sends the decompiled code of a function from IDA Pro to a local Ollama server and returns suggestions for renaming and comments. This makes it easy to assign meaningful names to variables, functions, and structures while you work.

## Purpose and interaction with Ollama

The plugin connects the Hex‑Rays decompiler to local Ollama language models. Function code is sent to Ollama over HTTP, the model analyzes it and returns a JSON response with new names and comments. AI Assistant applies these changes in IDA Pro. You can select different models and enable **thinking** mode so the assistant explains its reasoning in detail.

## Step-by-step installation

1. Copy all repository files into the `plugins` directory of your IDA Pro installation.
2. Ensure that `ai_assistant_settings.ini` is present. Adjust `ollama_url` and the `available_models` list if needed.
3. Install the Python dependencies (`requests`, `pydantic`, `PyQt5`).
4. Launch IDA Pro. The **AI Assistant** entry will appear in the Hex‑Rays context menu.

## Main features

- Analyze the selected function along with its surrounding code.
- Rename variables, structures, and called functions.
- Add a short comment describing the function.
- **Thinking** mode generates a detailed explanation and reasoning for the suggested names.
- Flexible configuration of models and prompts through the settings dialog.
- Debug messages can be enabled via the **Log level** drop-down in the settings.

## Requirements

- IDA Pro 7.7 or newer with Python 3 support.
- Installed Python modules: `requests`, `pydantic`, `PyQt5` (for the settings dialog).
- Running Ollama server version 0.2+ with your chosen models.

## Example usage

1. Open a function in the Hex‑Rays pseudocode window.
2. Right-click and select **AI Assistant → <model name>**.
3. The plugin sends the code to the Ollama server and applies new names and a comment within a few seconds.
4. When thinking mode is enabled, results include an additional reasoning block that can be logged.

## Common issues

- **Cannot connect to Ollama.** Check the `ollama_url` in the ini file and ensure the server is running.
- **Python dependencies not found.** Verify that `requests`, `pydantic`, and `PyQt5` are available to IDA.
- **Menu item does not appear.** Make sure the plugin files are in the correct directory and restart IDA.

This plugin is not affiliated with or endorsed by Hex-Rays SA
