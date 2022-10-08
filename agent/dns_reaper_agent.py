"""SubJak [https://github.com/haccer/subjack](subjack) tool implementation as ostorlab agent"""
import json
import logging
import subprocess
import tempfile
from typing import List

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
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


class SubJakAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin):
    """Proccess the message and emit the findings"""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        """Procces only message of type v3.asset.domain_name"""
        domain_name = message.data.get("name")
        if domain_name is not None and self.set_add(b'agent_subjack', f'{domain_name}'):
            logger.info('proccessing domain name: %s', domain_name)
            output_file = self._run_subjack_command(domain_name)
            findings = self._parse_subjack_output(output_file)
            self._emit_findings(findings)

    def _emit_findings(self, findings: List[str]) -> None:
        """Emit findings as a vulnurability"""
        for finding in findings:
            if finding["vulnerable"] is True:
                technical_detail = f""" subdomain {finding["subdomain"]} is vulnerable to subdomain takeover. service {finding["service"]}
                ```{finding}```
                """
                self.report_vulnerability(entry=kb.KB.SUBDOMAIN_TAKEOVER,
                                          technical_detail=technical_detail,
                                          risk_rating=vuln_mixin.RiskRating.HIGH)

    def _run_subjack_command(self, domain) -> str:
        output_file = tempfile.NamedTemporaryFile(suffix='.json')
        command = ['subjack', '-v', '-a', '-o', output_file.name, '-m', '-c', '/app/agent/fingerprints.json', '-d',
                   domain, '-ssl']
        logger.info('running subjack with command "%s"', command)
        subprocess.run(command, check=True)
        logger.info('subjack finished')
        return output_file

    def _parse_subjack_output(self, output_file) -> List[dict]:
        logger.info('parsing subjack output')
        output_file.seek(0)
        output_data = output_file.read()
        output_file.close()
        return json.loads(output_data)


if __name__ == '__main__':
    logger.info('starting agent subjack ...')
    SubJakAgent.main()
