"""conftest.py for agent Fingerprint Generator. """
import pathlib
import tempfile
from typing import IO

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.runtimes import definitions as runtime_definitions

from agent import dns_reaper_agent

OSTORLAB_YAML_PATH = (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').absolute()


@pytest.fixture
def scan_message_domain_name() -> msg.Message:
    """Creates a dummy message of type v3.asset.ip.v4.port.service to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {'name': 'ostorlab.co'}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent() -> dns_reaper_agent.DnsReaperAgent:
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/agent_fingerprint_generator',
            redis_url='redis://redis')
        return dns_reaper_agent.DnsReaperAgent(definition, settings)


@pytest.fixture
def fake_output_file() -> IO[bytes]:
    """Creates a fake output file for testing purposes.
    """
    output_file = tempfile.TemporaryFile(suffix='.json')
    output_file.write(b"""
[
  {
    "domain": "09090chromedevtools.github.io",
    "signature": "github_pages",
    "info": " The defined domain has A/AAAA records configured for Github Pages and but a web request shows the domain is unclaimed. An attacker can register this domain on Github Pages and serve their own web content.",
    "confidence": "CONFIRMED",
    "a_records": [
      "185.199.109.153",
      "185.199.111.153",
      "185.199.110.153",
      "185.199.108.153"
    ],
    "aaaa_records": [
      "2606:50c0:8000::153",
      "2606:50c0:8001::153",
      "2606:50c0:8002::153",
      "2606:50c0:8003::153"
    ],
    "cname_records": [],
    "ns_records": []
  }
]
    """)
    output_file.seek(0)
    return output_file
