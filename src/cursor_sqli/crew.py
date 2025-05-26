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
    _agent_cache = {}  # Cache to store agent instances

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    
    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def reconnaissance_agent(self) -> Agent:
        if 'reconnaissance_agent' not in self._agent_cache:
            self._agent_cache['reconnaissance_agent'] = Agent(
                config=self.agents_config['reconnaissance_agent'],
                tools=[ScrapeWebsiteTool(), SeleniumScrapingTool(), FirefoxSeleniumScrapingTool()],
                verbose=True
            )
        return self._agent_cache['reconnaissance_agent']

    @agent
    def scanner_agent(self) -> Agent:
        if 'scanner_agent' not in self._agent_cache:
            self._agent_cache['scanner_agent'] = Agent(
                config=self.agents_config['scanner_agent'],
                tools=[SQLInjectionScannerTool(), DatabaseIdentifierTool()],
                verbose=True
            )
        return self._agent_cache['scanner_agent']

    @agent
    def payload_generator_agent(self) -> Agent:
        if 'payload_generator_agent' not in self._agent_cache:
            self._agent_cache['payload_generator_agent'] = Agent(
                config=self.agents_config['payload_generator_agent'],
                tools=[PayloadGeneratorTool(), WAFEvasionTool()],
                verbose=True
            )
        return self._agent_cache['payload_generator_agent']

    @agent
    def executor_agent(self) -> Agent:
        if 'executor_agent' not in self._agent_cache:
            self._agent_cache['executor_agent'] = Agent(
                config=self.agents_config['executor_agent'],
                tools=[BrowserAutomationTool(), FirefoxBrowserAutomationTool(), ResponseAnalyzerTool()],
                verbose=True
            )
        return self._agent_cache['executor_agent']

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
            max_task_retries=0  # Prevent task retries
        )
