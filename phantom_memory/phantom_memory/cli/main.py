"""
PHANTOM MEMORY CLI.

Commands: ingest, normalize, graph, episode, memory, search, replay,
reconstruct, similarity, investigate, snapshot, compare, benchmark, report.

Runs the backend headless — no frontend required — so it can drive CI/CD
pipelines or batch research jobs.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.system import PhantomMemorySystem

app = typer.Typer(help="PHANTOM MEMORY — Security Memory Reconstruction Platform CLI")
graph_app = typer.Typer(help="Graph traversal and inspection commands.")
episode_app = typer.Typer(help="Episode reconstruction and lifecycle commands.")
memory_app = typer.Typer(help="Temporal memory queries.")
search_app = typer.Typer(help="Hybrid retrieval and similarity search.")
replay_app = typer.Typer(help="Event replay control.")
investigate_app = typer.Typer(help="Cases, notebooks, and bookmarks.")
snapshot_app = typer.Typer(help="Snapshot management.")

app.add_typer(graph_app, name="graph")
app.add_typer(episode_app, name="episode")
app.add_typer(memory_app, name="memory")
app.add_typer(search_app, name="search")
app.add_typer(replay_app, name="replay")
app.add_typer(investigate_app, name="investigate")
app.add_typer(snapshot_app, name="snapshot")

_DEFAULT_DATA_DIR = "data"


def _system(data_dir: str = _DEFAULT_DATA_DIR) -> PhantomMemorySystem:
    return PhantomMemorySystem(data_dir=data_dir)


def _print_json(obj) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str, ensure_ascii=False))


# --------------------------------------------------------------------------- #
# ingest / normalize
# --------------------------------------------------------------------------- #

@app.command()
def ingest(
    file: Path = typer.Argument(..., help="Path to a JSON array or NDJSON file of canonical events."),
    data_dir: str = typer.Option(_DEFAULT_DATA_DIR, help="Data directory for the event store/graph."),
):
    """Ingest canonical security events from a file."""
    system = _system(data_dir)
    text = file.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        raw_events = json.loads(text)
    else:
        raw_events = [json.loads(line) for line in text.splitlines() if line.strip()]

    accepted, duplicates, rejected = 0, 0, 0
    for raw in raw_events:
        event = CanonicalSecurityEvent.model_validate(raw)
        result = system.ingest(event)
        if result.accepted:
            accepted += 1
        elif result.was_duplicate:
            duplicates += 1
        else:
            rejected += 1
            typer.secho(f"rejected {event.event_id}: {result.reason}", fg=typer.colors.RED)

    _print_json({"accepted": accepted, "duplicates": duplicates, "rejected": rejected, "total": len(raw_events)})


@app.command()
def normalize(
    file: Path = typer.Argument(..., help="Path to a JSON array of raw events to validate/normalize."),
):
    """Validate and canonicalize events without writing them to the store (dry run)."""
    text = file.read_text(encoding="utf-8").strip()
    raw_events = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
    normalized = []
    errors = []
    for i, raw in enumerate(raw_events):
        try:
            event = CanonicalSecurityEvent.model_validate(raw)
            event = event.finalize()
            normalized.append(event.model_dump(mode="json"))
        except Exception as exc:
            errors.append({"index": i, "error": str(exc)})
    _print_json({"normalized_count": len(normalized), "error_count": len(errors), "errors": errors})


# --------------------------------------------------------------------------- #
# graph
# --------------------------------------------------------------------------- #

@graph_app.command("summary")
def graph_summary(data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json({"nodes": system.graph.node_count(), "edges": system.graph.edge_count()})


@graph_app.command("neighbors")
def graph_neighbors(
    entity_id: str, depth: int = 2, limit: int = 100, data_dir: str = _DEFAULT_DATA_DIR
):
    from phantom_memory.graph.search import GraphQueryOptions

    system = _system(data_dir)
    opts = GraphQueryOptions(depth_limit=depth, result_limit=limit)
    _print_json(system.graph_search.neighbors(entity_id, opts))


@graph_app.command("paths")
def graph_paths(
    source: str, target: str, k: int = 3, depth: int = 6, data_dir: str = _DEFAULT_DATA_DIR
):
    from phantom_memory.graph.search import GraphQueryOptions

    system = _system(data_dir)
    opts = GraphQueryOptions(depth_limit=depth)
    results = system.graph_search.shortest_paths(source, target, opts, k=k)
    _print_json([{"path": r.path, "confidence": r.total_confidence} for r in results])


# --------------------------------------------------------------------------- #
# episode
# --------------------------------------------------------------------------- #

@episode_app.command("reconstruct")
def episode_reconstruct(
    start_time: Optional[datetime] = typer.Option(None),
    end_time: Optional[datetime] = typer.Option(None),
    data_dir: str = _DEFAULT_DATA_DIR,
):
    system = _system(data_dir)
    episodes = system.reconstruct_episodes(start_time, end_time)
    _print_json([e.model_dump(mode="json") for e in episodes])


@episode_app.command("list")
def episode_list(data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json([e.model_dump(mode="json") for e in system.episode_store.all()])


@episode_app.command("show")
def episode_show(episode_id: str, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    ep = system.episode_store.get(episode_id)
    if ep is None:
        typer.secho(f"episode {episode_id} not found", fg=typer.colors.RED)
        raise typer.Exit(1)
    _print_json(ep.model_dump(mode="json"))


@episode_app.command("validate")
def episode_validate(episode_id: str, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.episode_lifecycle.validate(episode_id).model_dump(mode="json"))


@episode_app.command("reject")
def episode_reject(episode_id: str, reason: str = "", data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.episode_lifecycle.reject(episode_id, reason).model_dump(mode="json"))


@episode_app.command("close")
def episode_close(episode_id: str, notes: str = "", data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.episode_lifecycle.close(episode_id, notes).model_dump(mode="json"))


@episode_app.command("merge")
def episode_merge(episode_ids: list[str], title: Optional[str] = None, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.episode_lifecycle.merge(episode_ids, title).model_dump(mode="json"))


# --------------------------------------------------------------------------- #
# memory (temporal queries)
# --------------------------------------------------------------------------- #

@memory_app.command("state-at")
def memory_state_at(at_time: datetime, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(asdict(system.temporal_memory.state_at(at_time)))


@memory_app.command("entity-timeline")
def memory_entity_timeline(entity_id: str, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.temporal_memory.entity_timeline(entity_id))


@memory_app.command("diff")
def memory_diff(from_time: datetime, to_time: datetime, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(asdict(system.temporal_diff.diff(from_time, to_time)))


# --------------------------------------------------------------------------- #
# search / similarity
# --------------------------------------------------------------------------- #

@search_app.command("hybrid")
def search_hybrid(query: str, top_k: int = 20, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    episodes = system.episode_store.all()
    corpus = {ep.episode_id: f"{ep.title} {ep.episode_type} {' '.join(ep.entity_ids)}" for ep in episodes}
    hits = system.hybrid_retrieval.search(query, corpus=corpus, top_k=top_k)
    _print_json([h.__dict__ for h in hits])


@app.command()
def similarity(episode_id: str, top_k: int = 5, data_dir: str = _DEFAULT_DATA_DIR):
    """Find historically similar episodes/incidents for the given episode."""
    from phantom_memory.retrieval.similarity import IncidentFingerprint

    system = _system(data_dir)
    subject_ep = system.episode_store.get(episode_id)
    if subject_ep is None:
        typer.secho(f"episode {episode_id} not found", fg=typer.colors.RED)
        raise typer.Exit(1)

    def fp(ep):
        events = [system.store.get(eid) for eid in ep.event_ids]
        events = [e for e in events if e is not None]
        return IncidentFingerprint.from_events(ep.episode_id, events)

    subject_fp = fp(subject_ep)
    candidates = [fp(e) for e in system.episode_store.all() if e.episode_id != episode_id]
    results = system.similarity.rank(subject_fp, candidates, top_k=top_k)
    _print_json([r.as_dict() for r in results])


# --------------------------------------------------------------------------- #
# replay
# --------------------------------------------------------------------------- #

@replay_app.command("load")
def replay_load(
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, data_dir: str = _DEFAULT_DATA_DIR
):
    system = _system(data_dir)
    progress = system.replay.load(start_time=start_time, end_time=end_time)
    _print_json(progress.__dict__)


@replay_app.command("play")
def replay_play(max_events: Optional[int] = None, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    progress = system.replay.play(lambda e: system._project_to_graph(e), max_events=max_events)
    _print_json(progress.__dict__)


# --------------------------------------------------------------------------- #
# snapshot / compare
# --------------------------------------------------------------------------- #

@snapshot_app.command("create")
def snapshot_create(at_time: datetime, label: Optional[str] = None, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    snap = system.snapshots.create_snapshot(at_time, label)
    _print_json(snap.__dict__)


@snapshot_app.command("list")
def snapshot_list(data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.snapshots.list_snapshots())


@app.command()
def compare(from_time: datetime, to_time: datetime, data_dir: str = _DEFAULT_DATA_DIR):
    """Alias for `memory diff` — compares two points in system history."""
    system = _system(data_dir)
    _print_json(asdict(system.temporal_diff.diff(from_time, to_time)))


# --------------------------------------------------------------------------- #
# investigate
# --------------------------------------------------------------------------- #

@investigate_app.command("create-case")
def investigate_create_case(title: str, analyst: str, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json(system.cases.create(title, analyst).__dict__)


@investigate_app.command("list-cases")
def investigate_list_cases(state: Optional[str] = None, data_dir: str = _DEFAULT_DATA_DIR):
    system = _system(data_dir)
    _print_json([c.__dict__ for c in system.cases.list_cases(state)])


@investigate_app.command("bookmark")
def investigate_bookmark(
    subject_type: str, subject_ref: str, annotation: str, analyst: str, data_dir: str = _DEFAULT_DATA_DIR
):
    system = _system(data_dir)
    _print_json(system.bookmarks.create(subject_type, subject_ref, annotation, analyst).__dict__)


# --------------------------------------------------------------------------- #
# benchmark / report
# --------------------------------------------------------------------------- #

@app.command()
def benchmark(
    event_count: int = typer.Option(2000, help="Number of synthetic events to generate and ingest."),
    data_dir: str = typer.Option("data/benchmark_tmp", help="Scratch data directory for the benchmark."),
):
    """Reconstruction Benchmark Lab (lightweight): ingests N synthetic
    events and reports ingestion throughput, graph growth, episode
    reconstruction time, and query latency."""
    import shutil
    import uuid
    from datetime import timedelta, timezone

    from phantom_memory.core.models import EventCategory, ProvenanceMetadata, ProvenanceSource, TimestampInfo

    shutil.rmtree(data_dir, ignore_errors=True)
    system = _system(data_dir)

    base = datetime.now(timezone.utc)
    events = []
    for i in range(event_count):
        events.append(
            CanonicalSecurityEvent(
                event_id=f"evt_bench_{uuid.uuid4().hex}",
                event_type="process.exec" if i % 2 == 0 else "network.connect",
                event_category=EventCategory.PROCESS if i % 2 == 0 else EventCategory.NETWORK_CONNECTION,
                timestamps=TimestampInfo(event_time=base + timedelta(seconds=i)),
                source=ProvenanceMetadata(source=ProvenanceSource.SYNTHETIC),
                actor_entity_id=f"ent_process_bench_{i % 50}",
                target_entity_id=f"ent_process_bench_{(i + 1) % 50}",
                host_id=f"host-{i % 5}",
                payload_metadata={"process_name": f"proc_{i % 20}"},
            )
        )

    t0 = time.monotonic()
    for e in events:
        system.ingest(e)
    ingest_elapsed = time.monotonic() - t0

    t0 = time.monotonic()
    episodes = system.reconstruct_episodes()
    reconstruct_elapsed = time.monotonic() - t0

    t0 = time.monotonic()
    _ = system.store.query(limit=1000)
    query_elapsed = time.monotonic() - t0

    _print_json({
        "event_count": event_count,
        "ingest_seconds": round(ingest_elapsed, 4),
        "events_per_second": round(event_count / ingest_elapsed, 2) if ingest_elapsed > 0 else None,
        "episode_reconstruction_seconds": round(reconstruct_elapsed, 4),
        "episode_count": len(episodes),
        "query_1000_seconds": round(query_elapsed, 4),
        "graph_nodes": system.graph.node_count(),
        "graph_edges": system.graph.edge_count(),
    })


@app.command()
def report(episode_id: str, data_dir: str = _DEFAULT_DATA_DIR, output: Optional[Path] = None):
    """Generate a provenance-preserving Markdown report for an episode."""
    system = _system(data_dir)
    ep = system.episode_store.get(episode_id)
    if ep is None:
        typer.secho(f"episode {episode_id} not found", fg=typer.colors.RED)
        raise typer.Exit(1)

    events = [system.store.get(eid) for eid in ep.event_ids]
    events = [e for e in events if e is not None]
    events.sort(key=lambda e: e.timestamps.event_time)
    confidence = system.confidence.score_episode(ep, events)

    lines = [
        f"# Episode Report: {ep.title}",
        "",
        f"- **Episode ID:** `{ep.episode_id}`",
        f"- **Type:** {ep.episode_type}",
        f"- **Status:** {ep.status}",
        f"- **Start:** {ep.start_time}",
        f"- **End:** {ep.end_time}",
        f"- **Confidence:** {confidence.final} "
        f"(source_reliability={confidence.source_reliability}, "
        f"temporal_consistency={confidence.temporal_consistency})",
        "",
        "## Entities",
        *(f"- `{eid}`" for eid in ep.entity_ids),
        "",
        "## Event Timeline (evidence)",
    ]
    for e in events:
        lines.append(f"- `{e.timestamps.event_time.isoformat()}` — `{e.event_id}` — {e.event_type} "
                      f"(actor=`{e.actor_entity_id}`, target=`{e.target_entity_id}`)")

    content = "\n".join(lines)
    if output:
        output.write_text(content, encoding="utf-8")
        typer.echo(f"report written to {output}")
    else:
        typer.echo(content)


if __name__ == "__main__":
    app()
