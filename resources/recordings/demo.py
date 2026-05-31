import asyncio

from admina import GovernedModel
from admina.plugins.builtin.adapters.ollama import OllamaAdapter

PROMPT = "John Smith here (john@acme.com, card 4111 1111 1111 1111). Say just: hi"


async def main():
    # Wrap any model — every call is governed (PII redacted, audited)
    adapter = OllamaAdapter(default_model="gemma3:1b")
    model = GovernedModel(model_name="gemma3:1b", adapter=adapter)
    r = await model.ask(PROMPT, options={"num_predict": 18, "temperature": 0})

    seen = model._get_pii_redactor().redact(PROMPT)
    print(f"\n  you send  : {PROMPT}")
    print(f"  model sees: {seen['redacted_text']}")
    print(f"  stripped  : {seen['count']} PII entities — before the model ever saw them")
    print(f"  reply     : {r.text.strip()}\n")


asyncio.run(main())
