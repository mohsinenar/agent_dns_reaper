"""Unittests for agent."""


def testSubJackAgent_whenSubDomainVulnerabilityIsFound_thenVulnerabilityIsReported(test_agent, agent_mock, mocker,
                                                                                   scan_message_domain_name,
                                                                                   fake_ouput_file, agent_persist_mock):
    """Test that a vulnerability is reported when a subdomain is found."""
    mocker.patch('agent.subjack_agent.SubJakAgent._run_subjack_command', return_value=fake_ouput_file)

    test_agent.process(scan_message_domain_name)
    test_agent.process(scan_message_domain_name)

    assert len(agent_mock) == 1
    assert agent_mock[0].data.get('title') == 'Subdomain Takeover'
    assert 'subdomain cadkncsjdan.github.io is vulnerable to subdomain takeover' in agent_mock[0].data.get(
        'technical_detail')
