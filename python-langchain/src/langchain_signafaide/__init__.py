"""signafAIde for LangChain.

    from langchain.agents import create_agent
    from langchain_signafaide import SignafaideMiddleware

    agent = create_agent(model, tools=tools, middleware=[SignafaideMiddleware(agent="support-bot")])

Every tool call the agent makes writes a signed ``decision`` record before the tool runs and an
``outcome`` record after it. Records are chained on the machine that wrote them, in
``.signafaide/``; nothing is sent until a person opts in (``signafaide init``, or
``SIGNAFAIDE_API_KEY``).
"""

from signafaide import NotRecorded, wrap_tool, wrap_tools

from .middleware import SignafaideMiddleware

__version__ = "0.1.0"

__all__ = ["SignafaideMiddleware", "wrap_tools", "wrap_tool", "NotRecorded", "__version__"]
