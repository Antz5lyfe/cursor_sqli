from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
from cursor_sqli.tools import (
    ScrapeWebsiteTool, 
    SeleniumScrapingTool,
    FirefoxSeleniumScrapingTool,
    SQLInjectionScannerTool, 
    DatabaseIdentifierTool,
    PayloadGeneratorTool, 
    WAFEvasionTool,
    BrowserAutomationTool, 
    ResponseAnalyzerTool,
    FirefoxBrowserAutomationTool
)
# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class CursorSqli():
    """SQL Injection Tool based on CrewAI"""

    agents: List[BaseAgent]
    tasks: List[Task]

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    
    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def reconnaissance_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['reconnaissance_agent'],
            tools=[ScrapeWebsiteTool(), SeleniumScrapingTool(), FirefoxSeleniumScrapingTool()],
            verbose=True
        )

    @agent
    def scanner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['scanner_agent'],
            tools=[SQLInjectionScannerTool(), DatabaseIdentifierTool()],
            verbose=True
        )

    @agent
    def payload_generator_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['payload_generator_agent'],
            tools=[PayloadGeneratorTool(), WAFEvasionTool()],
            verbose=True
        )

    @agent
    def executor_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['executor_agent'],
            tools=[BrowserAutomationTool(), ResponseAnalyzerTool(), FirefoxBrowserAutomationTool()],
            # Adding a context message for proper tool usage
            context="""
            IMPORTANT: When using the FirefoxBrowserAutomationTool, always use the exact target URL from the task. 
            Do NOT use placeholder URLs like "http://targetwebsite.com".
            
            ⚠️ CRITICAL: You MUST use one of these exact formats for entry_point to prevent "invalid type: map" errors:
            
            1. Auto-detection (PREFERRED, MOST RELIABLE):
            ```
            entry_point = {
                'type': 'form_input'
            }
            ```
            
            2. Form fields with string selectors:
            ```
            entry_point = {
                'type': 'form_input',
                'form_fields': {
                    'email': 'input[type="email"]',  
                    'password': 'input[type="password"]'
                }
            }
            ```
            
            3. Single selector (use only if needed):
            ```
            entry_point = {
                'type': 'form_input',
                'selector': 'input#username',  # Must be a string, not a dictionary
                'selector_type': 'css'
            }
            ```
            
            COMMON ERRORS TO AVOID:
            - DO NOT nest dictionaries inside the 'selector' field
            - DO NOT use dictionary values where string values are expected
            - If you see "invalid type: map, expected a string" error, switch to auto-detection format
            
            For payloads, use one of these common SQL injection strings:
            - "' OR '1'='1"
            - "' OR '1'='1' --"
            - "admin' --"
            - "1' OR 1=1 --"
            
            Always set visible_mode to true when the --visible flag is provided with the command.
            """,
            verbose=True
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def reconnaissance_task(self) -> Task:
        return Task(
            config=self.tasks_config['reconnaissance_task'],
        )

    @task
    def scanning_task(self) -> Task:
        return Task(
            config=self.tasks_config['scanning_task'],
        )

    @task
    def payload_generation_task(self) -> Task:
        return Task(
            config=self.tasks_config['payload_generation_task'],
        )

    @task
    def execution_task(self) -> Task:
        return Task(
            config=self.tasks_config['execution_task'],
            output_file='sqli_report.md'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the SQL Injection crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
