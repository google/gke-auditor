# GKE Auditor

A tool to detect a set of common Google Kubernetes Engine misconfigurations.
Aimed to help security and development teams streamline configuration parts
 of their processes, and save time looking for generic bugs and vulnerabilities.

The tool consists of individual modules called Detectors, each scanning for a
 specific vulnerability.

This is not an officially supported Google product.

### Dependencies

- [JDK 11 or later](https://www.oracle.com/technetwork/java/javase/downloads/index.html)
- [Maven](https://maven.apache.org/)
- [Google Cloud SDK](https://cloud.google.com/sdk/install)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

To install the dependencies on Debian, run:
```bash
install-debian.sh
```

If the tool is run from a GCP Cloud shell, all the above mentioned dependencies
 should be pre-installed in the Shell.
To access the Cloud Shell, use the [Google Cloud Console](https://cloud.google.com/shell/docs/using-cloud-shell)
or [SSH](https://cloud.google.com/sdk/gcloud/reference/alpha/cloud-shell/ssh)
into it by running
```bash
gcloud alpha cloud-shell ssh
```
after installing the Google Cloud SDK into your local machine.

## Installation
```bash
git clone https://github.com/google/gke-auditor
cd ./gke-auditor/
./build.sh
```

## Authentication
Before running the tool, make sure to
[configure access to your cluster.](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl)
```bash
gcloud init
gcloud auth login
gcloud container clusters get-credentials CLUSTER_NAME --zone=ZONE
```

## Usage

The tool has to be built by running the **build.sh** script first.
 
Once the tool is built, it can be run using the **auditor.sh** script,
using the following options:
```bash
 ./auditor.sh [-a] [-ast] [-c] [-d] [-h] [-i <arg>] [-p <arg>] [-q]
       [-r <arg>]
 -a,--all          Run all detectors.
 -ast,--assets     Run all detectors for each individual asset.
 -c,--color        Turns on tool output coloring.
 -d,--defaults     Runs detectors including Kubernetes default assets.
                   Disabled by default.
 -h,--help         Print help information.
 -i,--iso <arg>    Run Node Isolation detectors.
                   To run all detectors, omit the argument list.
                   To specify individual detectors to run, give a list of
                   indices:
                   1. NODE_SELECTOR_POD_REJECTED
                   2. NODE_TAINTS_POD_REJECTED
                   3. NODE_AFFINITY_POD_REJECTED
 -p,--psp <arg>    Run PSP (Pod Security Policy) detectors.
                   To run all detectors, omit the argument list.
                   To specify individual detectors to run, give a list of
                   indices:
                   1. PRIVILEGED_CONTAINERS
                   2. CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE
                   3. CONTAINERS_SHARING_HOST_IPC
                   4. CONTAINER_SHARING_HOST_NETWORK_NAMESPACE
                   5. CONTAINERS_ALLOW_PRIVILEGE_ESCALATION
                   6. ROOT_CONTAINERS_ADMISSION
                   7. CONTAINERS_NET_RAW_CAPABILITY
                   8. CONTAINERS_ADDED_CAPABILITIES
                   9. CONTAINERS_CAPABILITIES_ASSIGNED
 -q,--quiet        Prints out only misconfigurations, without additional
                   detector info. Disabled by default.
 -r,--rbac <arg>   Run RBAC (Role Based Access Control) detectors.
                   To run all detectors, omit the argument list.
                   To specify individual detectors to run, give a list of
                   indices:
                   1. CLUSTER_ADMIN_ROLE_USED
                   2. SECRET_ACCESS_ALLOWED
                   3. WILDCARD_USED
                   4. CREATE_PODS_ALLOWED
                   5. AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_ENABLED
                   6. ESCALATING_RESOURCES_REPORT
```

## Examples
### Run all detectors
```
./auditor.sh
```
or
```
./auditor.sh --all
```

### Run specific detectors
```
./auditor.sh --iso 1 --psp 2,3 --rbac 
```

This will run the first isolation detector (NODE_SELECTOR_POD_REJECTED),
second and third PSP detectors (CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE,
CONTAINERS_SHARING_HOST_IPC) and all RBAC detectors.

Detectors can be chosen by specifying a list of indices in accordance with
the lists given in the help section of the tool.

### Run detectors for individual assets
```
./auditor.sh --assets # Runs all detectors.
./auditor.sh --assets --iso 0 --psp 1,2 --rbac  # Runs only specified detectors.
```

A detector auditing assets for vulnerabilities individually: instead of running
a detector on all available assets, runs all detectors on a single asset
at a time.

## Additional features 

In addition to the above listed example, the tool can be run with following
options:

### Coloring

```
./auditor.sh -c
```

Vulnerabilities will be colored in red.

### Quiet mode

```
./auditor.sh -q
```

Quiet mode: no additional information about vulnerabilities will be printed out
besides the detector names and vulnerable assets found.

### Including K8s defaults

```
./auditor.sh -d
```

Includes K8s defaults in the audit.

A default K8s cluster will have some configurations which might be considered
vulnerable by the tool.
Those configurations are excluded from the audit by default, but including those
defaults might be useful for some researchers (e.g. those auditing K8s itself).

## Detector Information

For detailed information about the vulnerabilities the detectors are checking
 for, refer to [OUTPUTS.md](OUTPUTS.md).

## References

Some of the implemented detectors refer to
[CIS Benchmarks](https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

```
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
