from .policy_loader import PolicyLoader
from .executor import ExecutionEngine
from .execution_logger import ExecutionLogger


loader = PolicyLoader()

executor = ExecutionEngine()

logger = ExecutionLogger()


policies = loader.load("agent/results.json")

results = []

for policy in policies:

    results.append(

        executor.execute(policy)

    )

logger.write(

    results,

    "results/scheme_execution.csv"

)