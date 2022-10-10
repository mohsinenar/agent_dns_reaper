"""dnsReaper [https://github.com/punk-security/dnsReaper](dnsReaper) tool implementation as ostorlab agent"""
import json
import logging
import subprocess
import tempfile
from typing import List, IO, Dict, Any

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    level='INFO',
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


def _run_dns_reaper_command(domain: str, output_file: IO[bytes]) -> None:
    command = ['python3', '/app/dnsReaper/main.py',
               'single', '--domain', domain, '--out-format', 'json', '--out', output_file.name
               ]
    logger.info('running dnsReaper with command "%s"', ' '.join(command))
    subprocess.run(command, check=True)
    logger.info('dnsReaper finished')


def _parse_dns_reaper_output(output_file: IO[bytes]) -> Any:
    logger.info('parsing dnsReaper output')
    output_file.seek(0)
    output_data = output_file.read()
    logger.info(output_data)
    output_file.close()
    return json.loads(output_data)


class DnsReaperAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin):
    """Process the message and emit the findings"""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Process only message of type v3.asset.domain_name"""
        domain_name: str = message.data.get('name', '')
        if domain_name is not None and self.set_add(b'agent_dns_reaper', f'{domain_name}'):
            logger.info('processing domain name: %s', domain_name)
            with tempfile.NamedTemporaryFile(suffix='.json') as output_file:
                _run_dns_reaper_command(domain_name, output_file)
                findings = _parse_dns_reaper_output(output_file)
                self._emit_findings(findings)

    def _emit_findings(self, findings: List[
        Dict[Any, Any]]) -> None:
        """Emit findings as a vulnerability"""
        for finding in findings:
            if finding.get('confidence') == 'CONFIRMED':
                technical_detail = f"""```{finding}```"""
                self.report_vulnerability(entry=kb.KB.SUBDOMAIN_TAKEOVER,
                                          technical_detail=technical_detail,
                                          risk_rating=vuln_mixin.RiskRating.HIGH)


if __name__ == '__main__':
    logger.info('starting agent dnsReaper ...')
    DnsReaperAgent.main()
