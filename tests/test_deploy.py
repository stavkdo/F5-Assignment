"""The deployment files agree with each other and with the code. No cluster needed."""

import re

import yaml

from conftest import ROOT

DEPLOY = ROOT / "deploy"


def load(name):
    return yaml.safe_load((DEPLOY / name).read_text(encoding="utf-8"))


def container():
    return load("deployment.yaml")["spec"]["template"]["spec"]["containers"][0]


def test_configmap_is_the_same_as_rules_yaml():
    # The ConfigMap is a generated copy; editing one and not the other would deploy other rules.
    data = load("configmap.yaml")["data"]["rules.yaml"]
    assert data == (ROOT / "rules.yaml").read_text(encoding="utf-8"), (
        "deploy/configmap.yaml is out of date, regenerate it (command in its header)"
    )


def test_deployment_mounts_the_configmap_where_the_service_reads_it():
    deployment = load("deployment.yaml")
    pod = deployment["spec"]["template"]["spec"]
    c = container()
    rules_path = c["args"][c["args"].index("--rules") + 1]
    mount = next(m for m in c["volumeMounts"] if m["name"] == "rules")
    volume = next(v for v in pod["volumes"] if v["name"] == "rules")

    assert rules_path == mount["mountPath"] + "/rules.yaml"
    assert volume["configMap"]["name"] == load("configmap.yaml")["metadata"]["name"]
    assert "rules.yaml" in load("configmap.yaml")["data"]


def test_probes_and_ports_match_the_service():
    c = container()
    port = c["args"][c["args"].index("--addr") + 1]
    assert port == f":{c['ports'][0]['containerPort']}"
    for probe in ("readinessProbe", "livenessProbe"):
        assert c[probe]["httpGet"]["path"] == "/healthz"


def test_service_selects_the_deployment_pods():
    service, deployment = load("service.yaml"), load("deployment.yaml")
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    assert service["spec"]["selector"].items() <= labels.items()
    assert deployment["spec"]["selector"]["matchLabels"].items() <= labels.items()
    assert service["spec"]["ports"][0]["targetPort"] == container()["ports"][0]["name"]


def test_image_tag_matches_the_package_version():
    version = re.search(r'^version = "(.+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    assert container()["image"] == f"redactor:{version}"


def test_dockerfile_runs_as_non_root_and_without_baked_in_rules():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER 10001$", dockerfile, re.M)
    assert "COPY rules.yaml" not in dockerfile
    assert container()["securityContext"]["runAsNonRoot"] is True
