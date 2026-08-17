  #!/usr/bin/env bash
  # gen-policies.sh — emits 3 policies x 25k except-CIDRs = 75k entries (> 65536)
  POLICIES=3 ; PER=25000 ; n=0
  for p in $(seq 1 $POLICIES); do
    {
      echo "apiVersion: networking.k8s.io/v1"
      echo "kind: NetworkPolicy"
      echo "metadata: { name: flood-$p, namespace: default }"
      echo "spec:"
      echo "  podSelector: { matchLabels: { app: probe-target } }"
      echo "  policyTypes: [Ingress]"
      echo "  ingress:"
      echo "  - from:"
      echo "    - ipBlock:"
      echo "        cidr: 10.0.0.0/8"
      echo "        except:"
      for i in $(seq 1 $PER); do
        # distinct /32s inside 10.0.0.0/8
        printf '        - 10.%d.%d.%d/32\n' $(( (n/65536)%256 )) $(( (n/256)%256 )) $(( n%256 ))
        n=$((n+1))
      done
    } > "flood-$p.yaml"
  done
  echo "generated $((POLICIES*PER)) except CIDRs across $POLICIES policies"

