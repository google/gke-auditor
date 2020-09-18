# Outputs

This documents serves as guidance for interpreting the tool outputs.

## General detector output format

-  **Detector:** Detector name

-  **Explanation:** A short explanation of the concept that is being checked. 
Describes how and why the concept be a security issue. Often includes links to 
the documentation for more information.

-  **Remediation:** Steps to take in order to review the problem and resolve the
vulnerability.

-  **Useful links:** Links to the documentation or other resources where the 
customer can learn about the issues at hand.

-  **Level:** one of [VULNERABILITY, WARNING]. *VULNERABILITY* implies security 
recommendations are not being followed, whereas a *WARNING* is informational
and implies a potential vulnerability could exist.

-  **Severity:** one of [LOW, MEDIUM, HIGH]. Indicator of the seriousness of 
detected issues.

-  **Vulnerable assets:** List of assets that have the above described 
vulnerability.


Here is an example of the tool output:
```
Detector: CREATE_PODS_ALLOWED
        Explanation: The ability to create pods in a namespace can provide a 
number of opportunities for privilege escalation, such as assigning privileged 
service accounts to these pods or mounting hostPaths with access to sensitive 
data (unless Pod Security Policies are implemented to restrict this access. 
As such, access to create new pods should be restricted to the smallest
possible group of users. The ability to create pods in a cluster opens 
uppossibilities for privilege escalation and should be restricted, where
possible.
        Remediation: Review the users who have create access to pod objects in 
the Kubernetes API. Where possible, remove create access to pod objects in the 
cluster. Care should be taken not to remove access to pods to system components
 which require this for their operation.
        Useful links: [https://kubernetes.io/docs/admin/authorization/rbac]
        Level: VULNERABILITY
        Severity: MEDIUM

        ClusterRole: admin
                Rules:
                        ApiGroups: []
                        Verbs: [create, delete, deletecollection, patch, update]
                        Resources: [pods, pods/attach, pods/exec, 
pods/portforward, pods/proxy]

        ClusterRole: edit
                Rules:
                        ApiGroups: []
                        Verbs: [create, delete, deletecollection, patch, update]
                        Resources: [pods, pods/attach, pods/exec, 
pods/portforward, pods/proxy]

        ClusterRole: system:aggregate-to-edit
                Rules:
                        ApiGroups: []
                        Verbs: [create, delete, deletecollection, patch, update]
                        Resources: [pods, pods/attach, pods/exec, 
pods/portforward, pods/proxy]

```
## Implemented Detectors

<br>
<table>
<thead>
  <tr>
    <th>Detector Group</th>
    <th>Detector</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="6">Role Based Access Control</td>
    <td>CLUSTER_ADMIN_ROLE_USED</td>
  </tr>
  <tr>
    <td>SECRET_ACCESS_ALLOWED</td>
  </tr>
  <tr>
    <td>WILDCARD_USED</td>
  </tr>
  <tr>
    <td>CREATE_PODS_ALLOWED</td>
  </tr>
  <tr>
    <td>AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_ENABLED</td>
  </tr>
  <tr>
    <td>ESCALATING_RESOURCES_DEPENDENCY_REPORT</td>
  </tr>
 
  <tr>
    <td rowspan="3">Node Isolation</td>
    <td>NODE_SELECTOR</td>
  </tr>
  <tr>
    <td>NODE_AFFINITY</td>
  </tr>
  <tr>
    <td>NODE_TAINTS</td>
  </tr>
  <tr>
    <td rowspan="9">Pod Security Policy</td>
    <td>PRIVILEGED_CONTAINERS</td>
  </tr>
  <tr>
    <td>CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE</td>
  </tr>
  <tr>
    <td>CONTAINERS_SHARING_HOST_IPC</td>
  </tr>
  <tr>
    <td>CONTAINER_SHARING_HOST_NETWORK_NAMESPACE</td>
  </tr>
  <tr>
    <td>CONTAINERS_ALLOW_PRIVILEGE_ESCALATION</td>
  </tr>
  <tr>
    <td>ROOT_CONTAINERS_ADMISSION</td>
  </tr>
  <tr>
    <td>CONTAINERS_NET_RAW_CAPABILITY</td>
  </tr>
  <tr>
    <td>CONTAINERS_ADDED_CAPABILITIES</td>
  </tr>
  <tr>
    <td>CONTAINERS_CAPABILITIES_ASSIGNED</td>
  </tr>
</tbody>
</table>
<br>

## Detailed outputs

## Role Based Access Control (RBAC)

### CLUSTER_ADMIN_ROLE_USED

-   **Explanation:** Kubernetes provides a set of default roles where RBAC 
is used. Some of these roles such as cluster-admin provide wide-ranging 
privileges which should only be applied where absolutely necessary. Roles 
such as cluster-admin allow super-user access to perform any action on any 
resource. When used in a ClusterRoleBinding, it gives full control over every 
resource in the cluster and in all namespaces. When used in a RoleBinding, it 
gives full control over every resource in the RoleBinding's namespace, 
including the namespace itself.

-   **Remediation:** Identify all ClusterRoleBindings to the cluster-admin
role. Check if they are used and if they need this role or if they could use a
role with fewer privileges. Where possible, first bind users to a lower 
privileged role and then remove the clusterrolebinding to the cluster-admin
role. Care should be taken before removing any clusterrolebindings from the 
environment to ensure they were not required for operation of the cluster. 
Specifically, modifications should not be made to clusterrolebindings with 
the system: prefix as they are required for the operation of system components.

-   **Useful links:**


    -   [https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles](https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### ACCESS_TO_SECRETS

-   **Explanation:** The Kubernetes API stores secrets, which may be service 
account tokens for the Kubernetes API or credentials used by workloads in the 
cluster. Access to these secrets should be restricted to the smallest possible 
group of users to reduce the risk of privilege escalation. Inappropriate access 
to secrets stored within the Kubernetes cluster can allow for an attacker to 
gain additional access to the Kubernetes cluster or external resources whose 
credentials are stored as secrets.

-   **Remediation:** Review the users who have get, list or watch access to
secrets objects in the Kubernetes API. Where possible, remove access.
Care should be taken not to remove access to secrets to system components which
require this for their operation.

-   **Useful  links:**


    -   [https://kubernetes.io/docs/concepts/configuration/secret/](https://kubernetes.io/docs/concepts/configuration/secret/])


-   **Level**: VULNERABILITY

-   **Severity**: MEDIUM


### WILDCARD_USED

-   **Explanation**: Kubernetes Roles and ClusterRoles provide access to
resources based on sets of objects and actions that can be taken on those
objects. It is possible to set either of these to be the wildcard "*" which
matches all items. Use of wildcards is not optimal from a security perspective
as it may allow for inadvertent access to be granted when new resources are
added to the Kubernetes API either as CRDs or in later versions of the product.
The principle of least privilege recommends that users are provided only the
access required for their role and nothing more. The use of wildcard rights
grants is likely to provide excessive rights to the Kubernetes API.

-   **Remediation**: Where possible replace any use of wildcards in
clusterroles and roles with specific objects or actions.

-   **Useful**  **links**:


    -   [https://kubernetes.io/docs/admin/authorization/rbac](https://kubernetes.io/docs/admin/authorization/rbac)


-   **Level**: VULNERABILITY

-   **Severity**: MEDIUM


### CREATE_PODS_ALLOWED

-   **Explanation**: The ability to create pods in a namespace can provide a
number of opportunities for privilege escalation, such as assigning privileged
service accounts to these pods or mounting hostPaths with access to sensitive
data (unless Pod Security Policies are implemented to restrict this access.
As such, access to create new pods should be restricted to the smallest
possible group of users. The ability to create pods in a cluster opens
uppossibilities for privilege escalation and should be restricted,
where possible.

-   **Remediation**: Review the users who have create access to pod objects in
the Kubernetes API. Where possible, remove create access to pod objects in the
cluster. Care should be taken not to remove access to pods to system components
which require this for their operation.

-   **Useful  links:**


    -   [https://kubernetes.io/docs/admin/authorization/rbac](https://kubernetes.io/docs/admin/authorization/rbac])


-   **Level**: VULNERABILITY

-   **Severity**: MEDIUM


### AUTOMOUNT_SERVICE_ACCOUNT_TOKENS_ENABLED

-   **Explanation:** Service accounts tokens should not be mounted in pods
except where the workload running in the pod explicitly needs to communicate
with the API server. Mounting service account tokens inside pods can provide an
avenue for privilege escalation attacks where an attacker is able to compromise
a single pod in the cluster. Avoiding mounting these tokens removes this attack
avenue.

-   **Remediation**: Modify the definition of pods and service accounts which
do not need to mount service account tokens to disable it.

-   **Useful links:**


    -   [https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### ESCALATING_RESOURCES_DEPENDENCY_REPORT

-   **Explanation:** The dependency report searches for a path from a Node to a
Service Account with permissions on the Node and its resources
(Pods, Containers, Volume Mounts). There can be security implications if the
Service Account is over permissive.

-   **Remediation:** Review on which resources the Service Account has
permissions and remove the ones that are not completely neccessary.

-   **Useful links:**


    -   [https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


## Node Isolation

  

### NODE_SELECTOR

-   **Explanation:** nodeSelector is the simplest recommended form of node 
selection constraint. nodeSelector specifies a map of key-value pairs. For the 
pod to be eligible to run on a node, the node must have each of the indicated 
key-value pairs as labels (it can have additional labels as well). The most 
common usage is one key-value pair.

-   **Remediation:** Review which pods were rejected by nodes and ensure this 
complies with the desired behaviour.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector)


-   **Level:** WARNING

-   **Severity:** LOW


### NODE_AFFINITY

-   **Explanation:** Node affinity allows you to constrain which nodes your pod
is eligible to be scheduled on, based on labels on the node. It is conceptually
similar to nodeSelector, but greatly expands types of constraints you can 
express.

-   **Remediation:** Review which pods were rejected by nodes and ensure this 
complies with the desired behaviour.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity)


-   **Level:** WARNING

-   **Severity:** LOW


### NODE_TAINT

-   **Explanation:** Taints allow a node to repel a set of pods. Tolerations are
applied to pods, and allow (but do not require) the pods to schedule onto nodes
with matching taints. Taints and tolerations work together to ensure that pods
are not scheduled onto inappropriate nodes. One or more taints are applied to
a node; this marks that the node should not accept any pods that do not 
tolerate the taints.

-   **Remediation:** Review which pods were rejected by nodes and ensure this
complies with the desired behaviour.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)


-   **Level:** WARNING

-   **Severity:** LOW


## Pod Security Policy

### PRIVILEGED_CONTAINERS

-   **Explanation:** Privileged containers have access to all Linux Kernel
capabilities and devices. A container running with full privileges can do almost
everything that the host can do. This flag exists to allow special use-cases,
like manipulating the network stack and accessing devices. There should be at
least one PodSecurityPolicy (PSP) defined which does not permit privileged
containers.

-   **Remediation:** If you have need to run containers which require
privileges, this should be defined in an separate PSP and you should carefully
check RBAC controls to ensure that only limited service accounts and users are
given permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the .spec.privileged field is omitted or set
to false.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged)

    -    [https://www.nccgroup.com/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/](https://www.nccgroup.com/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE

-   **Explanation:** A container running in the host's PID namespace can inspect
processes running outside the container. If the container also has access to
ptrace capabilities this can be used to escalate privileges outside of the
container. There should be at least one PodSecurityPolicy (PSP) defined which
does not permit containers to share the host PID namespace.

-   **Remediation:** If you have need to run containers which require hostPID,
this should be defined in an separate PSP and you should carefully check RBAC
controls to ensure that only limited service accounts and users are given
permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the .spec.hostPID field is omitted or set to false.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINERS_SHARING_HOST_IPC_NAMESPACE

-   **Explanation:** A container running in the host's IPC namespace can use IPC
to interact with processes outside the container. There should be at least one
PodSecurityPolicy (PSP) defined which does not permit containers to share the
host IPC namespace.

-   **Remediation:** If you have need to run containers which require hostIPC,
this should be defined in an separate PSP and you should carefully check RBAC
controls to ensure that only limited service accounts and users are given
permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the spec.hostIPC field is omitted or set to false.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)
    
-   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINER_SHARING_HOST_NETWORK_NAMESPACE

-   **Explanation:** A container running in the host's network namespace could
access the local loopback device, and could access network traffic to and from
other pods. There should be at least one PodSecurityPolicy (PSP) defined which
does not permit containers to share the host network namespace.

-   **Remediation:** If you have need to run containers which require
hostNetwork, this should be defined in an separate PSP and you should carefully
check RBAC controls to ensure that only limited service accounts and users are
given permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the spec.hostNetwork field is omitted or set to
false.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINER_ALLOW_PRIVILEGE_ESCALATION

-   **Explanation:** A container running with the allowPrivilegeEscalation flag
set to true may have processes that can gain more privileges than their parent.
There should be at least one PodSecurityPolicy (PSP) defined which does not
permit containers to allow privilege escalation. The option exists
(and is defaulted to true) to permit setuid binaries to run.

-   **Remediation:** If you have need to run containers which require setuid
binaries or require privilege escalation, this should be defined in an separate
PSP and you should carefully check RBAC controls to ensure that only limited
service accounts and users are given permission to access that PSP. Create a PSP
as described in the Kubernetes documentation, ensuring that the
.spec.allowPrivilegeEscalation field is omitted or set to false.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### ROOT_CONTAINERS_ADMISSION

-   **Explanation:** Containers may run as any Linux user. Containers which run
as the root user, whilst constrained by Container Runtime security features
still have an escalated likelihood of container breakout. Ideally, all
containers should run as a defined non-UID 0 user. There should be at least one
PodSecurityPolicy (PSP) defined which does not permit root users in a container.

-   **Remediation:** If you have need to run containers which require root
containers, this should be defined in an separate PSP and you should carefully
check RBAC controls to ensure that only limited service accounts and users are
given permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the spec.runAsUser.rule field is omitted or set to
either MustRunAsNonRoot or MustRunAs with the range of UIDs not including 0.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups)]


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINERS_NET_RAW_CAPABILITIES

-   **Explanation:** Containers run with a default set of capabilities as
assigned by the Container Runtime. By default, this can include potentially
dangerous capabilities. With Docker as the container runtime the NET_RAW
capability is enabled which may be misused by malicious containers. Ideally, all
containers should drop this capability. There should be at least one
PodSecurityPolicy (PSP) defined which prevents containers with the NET_RAW
capability from launching.

-   **Remediation:** If you have need to run containers which require NET_RAW
capability, this should be defined in an separate PSP and you should carefully
check RBAC controls to ensure that only limited service accounts and users are
given permission to access that PSP. Create a PSP as described in the Kubernetes
documentation, ensuring that the .spec.requiredDropCapabilities field is omitted
or set to either NET_RAW or ALL.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM


### CONTAINERS_ADDED_CAPABILITIES

-   **Explanation:** Containers run with a default set of capabilities as
assigned by the Container Runtime.Capabilities outside this set can be added to
containers which could expose them to risks of container breakout attacks.
There should be at least one PodSecurityPolicy (PSP) defined which prevents
containers with capabilities beyond the default set from launching.

-   **Remediation:** If you have need to run containers which require additional
capabilities, this should be defined in an separate PSP and you should carefully
check RBAC controls to ensure that only limited service accounts and users are
given permission to access that PSP. Ensure that allowedCapabilities is not
present in PSPs for the cluster unless it is set to an empty array.

-   **Useful links:**


    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities)


  -   **Level:** VULNERABILITY

  -   **Severity:** MEDIUM


### CONTAINERS_CAPABILITIES_ASSIGNED

-   **Explanation:** Containers run with a default set of capabilities as
assigned by the Container Runtime. Capabilities are parts of the rights
generally granted on a Linux system to the root user. In many cases applications
running in containers do not require any capabilities to operate, so from the
perspective of the principal of least privilege use of capabilities should be
minimized.

-   **Remediation:** Review the use of capabilities in applications running on
your cluster. Where a namespace contains applications which do not require any
Linux capabilities to operate consider adding a PSP which forbids the admission
of containers which do not drop all capabilities.

-   **Useful links:**

    -  [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies)

    -   [https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities)


-   **Level:** VULNERABILITY

-   **Severity:** MEDIUM