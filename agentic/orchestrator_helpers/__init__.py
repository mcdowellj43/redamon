"""Orchestrator helper functions.

This module contains helper functions extracted from the main orchestrator
to keep the architectural flow clear and maintainable.
"""

from .json_utils import (
    DateTimeEncoder,
    json_dumps_safe,
    normalize_content,
    extract_json,
)

from .parsing import (
    parse_llm_decision,
    try_parse_llm_decision,
    parse_analysis_response,
)

# config MUST be imported before phase/chain_graph_writer
# to avoid circular import: phase -> prompts -> utils -> orchestrator_helpers.get_checkpointer
from .config import (
    set_checkpointer,
    get_checkpointer,
    get_thread_id,
    create_config,
    get_config_values,
    get_identifiers,
    is_session_config_complete,
)

from .phase import (
    classify_attack_path,
    determine_phase_for_new_objective,
)

from .chain_graph_writer import (
    close_driver as close_chain_graph_driver,
)

from .debug import (
    save_graph_image,
)

from .llm_setup import (
    parse_model_provider,
    setup_llm,
    apply_project_settings,
)

from .streaming import (
    detect_generated_file,
    emit_streaming_events,
)

from .nodes import (
    initialize_node,
    think_node,
    execute_tool_node,
    generate_response_node,
    await_approval_node,
    process_approval_node,
    await_question_node,
    process_answer_node,
)

__all__ = [
    # json_utils
    "DateTimeEncoder",
    "json_dumps_safe",
    "normalize_content",
    "extract_json",
    # parsing
    "parse_llm_decision",
    "try_parse_llm_decision",
    "parse_analysis_response",
    # config
    "set_checkpointer",
    "get_checkpointer",
    "get_thread_id",
    "create_config",
    "get_config_values",
    "get_identifiers",
    "is_session_config_complete",
    # phase
    "classify_attack_path",
    "determine_phase_for_new_objective",
    # chain_graph_writer
    "close_chain_graph_driver",
    # debug
    "save_graph_image",
    # llm_setup
    "parse_model_provider",
    "setup_llm",
    "apply_project_settings",
    # streaming
    "detect_generated_file",
    "emit_streaming_events",
    # nodes
    "initialize_node",
    "think_node",
    "execute_tool_node",
    "generate_response_node",
    "await_approval_node",
    "process_approval_node",
    "await_question_node",
    "process_answer_node",
]
