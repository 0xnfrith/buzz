"""The checks of a child's environment fail without printing one.

Each check patches os.environ to a fixed fake parent holding the planted
dummies (planted_env.PLANTED_ENV) and compares variable names, never values
(planted_env.assert_names). Each row here runs one check with the code under
test made to leak: it hands the child this process's whole environment, as
the old deny-list code did. The check must fail, and its failure message
must hold none of the planted values.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import remote_sampler  # noqa: E402
import tenant_cogs  # noqa: E402
from planted_env import PLANTED_ENV  # noqa: E402


def leak_all() -> dict[str, str]:
    return dict(os.environ)


def leak_with(env: dict[str, str]) -> dict[str, str]:
    return {**os.environ, **env}


def leak_docker(endpoint: str, env: dict[str, str] | None = None) -> dict[str, str]:
    return {**os.environ, **(env or {}), "DOCKER_HOST": str(endpoint)}


# (the check, the code it guards, that code made to leak)
CHECKS = [
    ("test_tenant_cogs.SetupRateLimitTests.test_tenant_sim_env_drops_caller_credentials",
     (tenant_cogs, "child_env"), leak_all),
    ("test_tenant_cogs.SetupRateLimitTests.test_adapter_never_inherits_shell_overrides",
     (tenant_cogs, "without_limit_env"), leak_with),
    ("test_tenant_cogs.SetupRateLimitTests.test_up_raises_then_recreate_restores_defaults",
     (tenant_cogs, "without_limit_env"), leak_with),
    ("test_tenant_cogs.DockerEndpointTests.test_every_call_of_a_stack_goes_to_the_checked_endpoint",
     (tenant_cogs, "docker_env"), leak_docker),
    ("test_remote_sampler.Guard.test_the_argv_is_fixed",
     (remote_sampler, "ssh_env"), leak_all),
]


class ForcedFailures(unittest.TestCase):
    def test_each_check_fails_without_printing_an_environment(self) -> None:
        for name, (module, attr), leak in CHECKS:
            with self.subTest(check=name):
                suite = unittest.defaultTestLoader.loadTestsFromName(name)
                self.assertEqual(suite.countTestCases(), 1, "the check is found")
                result = unittest.TestResult()
                with mock.patch.object(module, attr, leak):
                    suite.run(result)
                self.assertEqual((len(result.failures), len(result.errors)), (1, 0),
                                 "the check fails (an assertion, not an error) on the leak")
                text = result.failures[0][1]
                # Only a yes or no: the message itself is never printed here.
                self.assertFalse(any(v in text for v in PLANTED_ENV.values()),
                                 "the failure message holds a planted value")


if __name__ == "__main__":
    unittest.main()
