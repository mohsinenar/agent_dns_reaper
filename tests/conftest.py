"""conftest.py for agent Fingerprint Generator. """
import pathlib
import tempfile

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import subjack_agent

OSTORLAB_YAML_PATH = (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').absolute()


@pytest.fixture
def scan_message_domain_name():
    """Creates a dummy message of type v3.asset.ip.v4.port.service to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {'name': 'ostorlab.co'}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent():
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/agent_fingerprint_generator',
            redis_url='redis://redis')
        return subjack_agent.SubJakAgent(definition, settings)


@pytest.fixture
def fake_ouput_file():
    """Creates a fake output file for testing purposes.
    """
    ouput_file = tempfile.TemporaryFile(suffix='.json')
    ouput_file.write(b"""
        [
          {
            "subdomain": "cadkncsjdan.github.io",
            "vulnerable": true,
            "service": "github"
          },
          {
            "subdomain": "cadkncsjdan-fale.github.io",
            "vulnerable": false,
            "service": "github"
          }
        ]
    """)
    return ouput_file
