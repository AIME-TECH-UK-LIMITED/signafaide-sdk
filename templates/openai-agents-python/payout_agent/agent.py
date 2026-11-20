"""One agent run: the model may call the tools. A tool the rules block does not run; the model gets
the reason as the tool's error and answers with it."""

from typing import Optional, Union

from agents import Agent, Model, RunConfig, Runner

from .tools import tools


def run_agent(prompt: str, model: Optional[Union[str, Model]] = None) -> str:
    from .scripted_model import ScriptedModel

    agent = Agent(
        name="payout-agent",
        instructions="You pay suppliers with approve_payout and look up invoices with lookup_invoice. Say what happened in one sentence.",
        tools=tools,
        model=model or ScriptedModel(),
    )
    # The scripted model needs no account, so nothing is traced to one either.
    result = Runner.run_sync(agent, prompt, max_turns=5, run_config=RunConfig(tracing_disabled=model is None))
    return str(result.final_output)
