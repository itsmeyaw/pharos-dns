# trace

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/trace/README.md)

## trace

- Pharos exports Zipkin v2 JSON over HTTP(S) from its own client rather than the OpenTracing/zipkin-go stack. Collector URL handling accepts `http://` and `https://` (case-insensitive scheme); URLs with userinfo are rejected.
- A bare Zipkin endpoint `host:port` becomes `http://host:port/api/v2/spans`, as in CoreDNS. A single positional argument is always an endpoint, never a type, so `trace datadog` names a Zipkin collector host called `datadog`.
- Sampling is `every N`: the Nth, 2Nth, ... Query is traced and `every 0` traces none, as in CoreDNS. The unsampled path costs one atomic increment and allocates nothing; `trace` also costs nothing per Query when not configured.
- Export never blocks a Query. Spans go to a bounded queue (`zipkin_max_backlog_size`, default 1000) that disposes the oldest span when full; a background task sends batches (`zipkin_max_batch_size` 100, `zipkin_max_batch_interval` 1s) with a 5s request timeout and no retry. Pharos counts outcomes in `pharos_trace_exported_spans_total` and `pharos_trace_dropped_spans_total{reason="queue_full"|"export_failed"}`; CoreDNS exports no trace metrics. A collector outage logs one line, not one per batch.
- Shutdown and Restart flush queued spans (bounded by the request timeout); a failed Reload restores the exporter.
- Trace IDs are 64-bit (16 hex digits), published as `trace/traceid` Metadata only when the metadata Plugin is active. Every Query starts a root span: Pharos does not read an incoming parent span, including the B3 header of a DoH request, so spans of a distributed trace are not linked.
- Spans carry `coredns.io/{name,type,rcode,proto,remote}` tags. With no Response written the returned status is the `rcode`; a Plugin error also gets the `error` tag and `event:error`/`error:<text>` annotations, as zipkin-go-opentracing does for log fields.
- The `datadog` endpoint type parses but the exporter is not implemented yet: Startup fails with an error naming it.
- Not covered by the differential harness: spans go to a collector the harness cannot observe. Loopback stub collector tests cover the wire format.
- The service endpoint's host is resolved once at Startup (first IPv4 and IPv6 address), as zipkin-go does; its port comes from the first key of the Server block (shortcut for multi-port blocks).

## Sources

- Derived from CoreDNS v1.15.0 plugin/trace/setup_test.go and trace_test.go.
- [CoreDNS v1.15.0 `plugin/trace`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/trace)
