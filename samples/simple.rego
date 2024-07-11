# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
package agent_policy

import future.keywords.in
import future.keywords.every

import input

default CreateContainerRequest := false

CreateContainerRequest {
    i_oci := input.OCI

    # Check if any element from the policy_data.containers array allows the input request.
    some p_container in policy_data.containers

    p_oci := p_container.OCI

    p_oci.Version == i_oci.Version

    allow_anno(p_oci, i_oci)
}

# Reject unexpected annotations.
allow_anno(p_oci, i_oci) {
    print("allow_anno 1: start")

    not i_oci.Annotations

    print("allow_anno 1: true")
}
allow_anno(p_oci, i_oci) {
    print("allow_anno 2: p Annotations =", p_oci.Annotations)
    print("allow_anno 2: i Annotations =", i_oci.Annotations)

    i_keys := object.keys(i_oci.Annotations)
    print("allow_anno 2: i keys =", i_keys)

    every i_key in i_keys {
        allow_anno_key(i_key, p_oci)
    }

    print("allow_anno 2: true")
}

allow_anno_key(i_key, p_oci) {
    print("allow_anno_key 1: i key =", i_key)

    startswith(i_key, "io.kubernetes.cri.")

    print("allow_anno_key 1: true")
}
allow_anno_key(i_key, p_oci) {
    print("allow_anno_key 2: i key =", i_key)

    some p_key, _ in p_oci.Annotations
    p_key == i_key

    print("allow_anno_key 2: true")
}

policy_data := {
  "containers": [
    {
      "OCI": {
        "Version": "1.1.0",
        "Annotations": {
          "io.katacontainers.pkg.oci.bundle_path": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/$(bundle-id)",
          "io.katacontainers.pkg.oci.container_type": "pod_sandbox",
          "io.kubernetes.cri.container-type": "sandbox",
          "io.kubernetes.cri.sandbox-id": "^[a-z0-9]{64}$",
          "io.kubernetes.cri.sandbox-log-directory": "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
          "io.kubernetes.cri.sandbox-name": "test",
          "io.kubernetes.cri.sandbox-namespace": "default",
          "nerdctl/network-namespace": "^/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        }
      }
    },
    {
      "OCI": {
        "Version": "1.1.0",
        "Annotations": {
          "io.katacontainers.pkg.oci.bundle_path": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/$(bundle-id)",
          "io.katacontainers.pkg.oci.container_type": "pod_container",
          "io.kubernetes.cri.container-name": "shell",
          "io.kubernetes.cri.container-type": "container",
          "io.kubernetes.cri.image-name": "ghcr.io/burgerdev/tmp/busybox:noenv",
          "io.kubernetes.cri.sandbox-id": "^[a-z0-9]{64}$",
          "io.kubernetes.cri.sandbox-name": "test",
          "io.kubernetes.cri.sandbox-namespace": "default"
        }
      }
    }
  ],
  "common": {
    "cpath": "/run/kata-containers/shared/containers"
  }
}
