# Distributed Architecture Overview

> **This chapter is planned for a future release.** It will cover:
>
> - Why distribute capture across multiple machines
> - The hunter/processor model
> - Network topologies (hub-and-spoke, hierarchical)
> - Security considerations for distributed deployments
>
> For current documentation, see `docs/DISTRIBUTED_MODE.md` in the repository.

```mermaid
flowchart TB
    subgraph Edge["Distributed Hunters"]
        direction LR
        H1[Hunter<br/>datacenter-1]
        H2[Hunter<br/>datacenter-2]
        H3[Hunter<br/>branch-office]
    end

    subgraph Processor["Processor Node"]
        P[Processor<br/>monitor.internal:55555]
        VIRT[Virtual Interface<br/>lc0]
    end

    subgraph Outputs[" "]
        direction LR
        subgraph Tools["Analysis Tools"]
            direction LR
            WS[Wireshark]
            TD[tcpdump]
            SNORT[Snort/Zeek]
        end

        PCAP[(PCAP Files)]

        subgraph Clients["Monitoring Clients"]
            direction LR
            TUI1[TUI Client]
            TUI2[TUI Client]
        end
    end

    H1 -->|gRPC/TLS| P
    H2 -->|gRPC/TLS| P
    H3 -->|gRPC/TLS| P
    VIRT --> Tools
    P --> PCAP
    P <-->|gRPC/TLS| Clients
```
