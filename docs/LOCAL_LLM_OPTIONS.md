# Local-Only LLM Options

These detectors run fully offline and do not call any hosted APIs. You can optionally pair them with a local language model to summarize findings or triage alerts without sending data off the box.

## Quick-start options

| Model | Download method | Notes |
| --- | --- | --- |
| Llama 3 8B Instruct | `ollama pull llama3` | Fast on modern CPUs, works in air-gapped environments after download. |
| Mistral 7B Instruct | `ollama pull mistral` | Strong general reasoning with small footprint. |
| Phi-3 Mini | `ollama pull phi3` | Light-weight option for older machines. |
| Gemma 2B/7B | `ollama pull gemma:2b` or `gemma:7b` | Google-aligned model with friendly licensing for local use. |
| Any GGUF model | Download `.gguf` from Hugging Face and load with `llama.cpp` | Works without an API key; great for bespoke hardware targets. |

## Example: run a local helper without an API key

1. Install [Ollama](https://ollama.com/download) (offline installers available).
2. Pull a model once (still offline if you pre-seed the image or use a local registry):
   ```bash
   ollama pull mistral
   ```
3. Pipe detector output into the model to summarize locally:
   ```bash
   ./scripts/master_detector.sh > raw_report.txt
   cat raw_report.txt | ollama run mistral "Summarize potential LLM persistence risks in this log"
   ```

Nothing in the detectors requires an API key or internet access; the suggestions above simply give you local models you can drop into your workflow.
