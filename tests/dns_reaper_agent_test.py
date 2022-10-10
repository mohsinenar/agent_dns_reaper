"""Unittests for agent."""
import json
from typing import List, Union, Dict, IO

from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import dns_reaper_agent


def testDnsReaperAgent_whenSubDomainVulnerabilityIsFound_thenVulnerabilityIsReported(
        test_agent: dns_reaper_agent.DnsReaperAgent,
        agent_mock: List[msg.Message],
        mocker: plugin.MockerFixture,
        scan_message_domain_name: msg.Message,
        fake_output_file: IO[bytes],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]]) -> None:
    """Test that a vulnerability is reported when a subdomain is found."""
    mocker.patch('agent.dns_reaper_agent._run_dns_reaper_command', return_value=None)
    mocker.patch('agent.dns_reaper_agent._parse_dns_reaper_output',
                 return_value=json.loads(fake_output_file.read()))

    test_agent.process(scan_message_domain_name)
    test_agent.process(scan_message_domain_name)

    assert len(agent_mock) == 1
    assert agent_mock[0].data.get('title') == 'Subdomain Takeover'
    assert 'defined domain has A/AAAA records configured' in agent_mock[0].data.get('technical_detail', '')
