# PHANTOM MEMORY — Security Memory Reconstruction Platform
### *(Backend Core Release)*

<p align="center">
  <em>Not another SIEM. A temporal memory for your infrastructure's security behavior.</em>
</p>

---

This repository contains the **backend core** of PHANTOM MEMORY: the event
model, temporal event store, security memory graph, episode reconstruction,
causal/divergence/confidence analysis, retrieval (vector + hybrid + historical
similarity), domain memory engines (process lineage, network sessions,
authentication, configuration), the investigation workspace (cases, notebook,
bookmarks), a versioned REST/WebSocket API, and a full CLI — all real,
runnable, and covered by an automated test suite (45 passing tests).

Components described in the full platform vision that are **not** included in
this release — kernel-level eBPF sensors, a distributed Kafka/NATS processing
layer, a production graph database deployment, and the Next.js frontend — are
intentionally left out rather than faked, so that everything in this
repository is genuine, working code. See **Roadmap** below.

Jump to: [English](#english) · [فارسی](#فارسی) · [中文](#中文)

---
<a name="english"></a>
## 🇬🇧 English

### What this is

PHANTOM MEMORY turns scattered, short-lived security events into a
**searchable, reconstructable, temporal memory** of a system's security
behavior. Instead of asking "what alert fired?", it is built to answer:

> *What actually happened, in what order, how are these events connected,
> where was the first point of divergence from normal behavior, what
> evidence supports this reconstruction, and has anything like this
> happened before?*

### What's implemented in this release

| Layer | Modules |
|---|---|
| **Core** | Canonical Security Event Model (Pydantic), immutable Temporal Event Store (SQLite; raw/normalized/enriched/derived layers), Clock Alignment Layer, Deduplication Engine, explainable Importance Engine |
| **Graph** | Security Memory Graph (temporal, versioned, evidence-carrying edges), Graph Search Engine (traversal / shortest paths / multi-hop, with depth limit, result limit, timeout, cancellation), Entity Resolution (reviewable/undoable merges) |
| **Temporal** | Point-in-time state reconstruction, Snapshot Engine, Temporal Diff Engine, Event Replay Engine (pause/resume/step/play/time-jump) |
| **Episodes** | Episode Reconstruction Engine (temporal proximity + graph connectivity, union-find grouping into Authentication / Process Execution / Network Communication / Configuration Change / Service Restart / File Access episodes), full lifecycle (candidate → validated → closed, merge/split with preserved provenance) |
| **Analysis** | Causal Hypothesis Engine (strict correlation-vs-causality distinction with graded evidence: direct / temporal / structural / similarity), First-Divergence Detection Engine, Contradiction Detector, Memory Confidence Engine, Evidence Completeness & Visibility Gap Detector |
| **Retrieval** | Local TF-IDF Vector Memory Index (no external model download required — privacy-aware by default), Hybrid Retrieval Engine (keyword + vector + graph + temporal), Historical Similarity Engine & Incident Fingerprinting, Incident Family clustering |
| **Domain memory** | Process Lineage Engine, Network Session Memory Engine, Authentication Memory Engine (identity → resource path tracing), Configuration Memory Engine & Diff Explorer |
| **Investigation workspace** | Case Management (Open → Triage → Investigating → Validated → Contained → Resolved → Closed), Investigation Notebook with a replayable Query Recorder, Evidence Bookmark System |
| **Ingestion** | `BaseConnector` interface (auth, incremental sync via cursor/checkpoint, retry with backoff, token-bucket rate limiting, backpressure, structured errors, provenance tagging) with two real implementations: a `FileConnector` (NDJSON log tailing) and a seeded `SyntheticSecurityUniverseGenerator` for safe, reproducible testing |
| **API** | FastAPI, versioned under `/api/v1/*` — events, graph, episodes, search, replay, cases, investigation — plus a live-updates WebSocket and a Self-Memory Health Layer (`/api/v1/health/*`) |
| **CLI** | `ingest`, `normalize`, `graph`, `episode`, `memory`, `search`, `replay`, `similarity`, `snapshot`, `compare`, `investigate`, `benchmark`, `report` |
| **Tests** | 45 automated tests: model integrity, event-store immutability, graph/search, episode reconstruction & lifecycle, causal reasoning, first-divergence, temporal/replay/snapshot/diff, similarity, case management, connectors, and a full end-to-end incident-reconstruction integration test |

### Installation

Requires **Python 3.10+**.

```bash
# 1. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (optional) install the package itself, including the `phantom-memory` CLI command
pip install -e .
```

### Running the tests

```bash
PYTHONPATH=. pytest tests/ -v
```

### Running the API

```bash
PYTHONPATH=. uvicorn phantom_memory.api.main:app --reload --port 8000
```

Then open `http://localhost:8000/docs` for interactive OpenAPI documentation,
or check platform health:

```bash
curl http://localhost:8000/api/v1/health/self
```

### Using the CLI

```bash
# Generate synthetic data and benchmark ingestion → episode reconstruction
PYTHONPATH=. python -m phantom_memory.cli.main benchmark --event-count 2000

# Ingest a file of canonical events (JSON array or NDJSON)
PYTHONPATH=. python -m phantom_memory.cli.main ingest events.json

# Reconstruct episodes from everything ingested so far
PYTHONPATH=. python -m phantom_memory.cli.main episode reconstruct

# List them
PYTHONPATH=. python -m phantom_memory.cli.main episode list

# See the full command tree
PYTHONPATH=. python -m phantom_memory.cli.main --help
```

### Project layout

```
phantom_memory/
  core/            canonical event model, event store, clock, dedup, importance
  graph/           security memory graph, search engine, entity resolution
  temporal/        state-at-time engine, snapshots, diff, replay
  episodes/        reconstruction engine, lifecycle management
  analysis/        causal hypotheses, first-divergence, contradictions, confidence, completeness
  retrieval/       vector index, hybrid retrieval, historical similarity
  domain/          process lineage, network sessions, authentication, configuration
  investigation/   case management, notebook, evidence bookmarks
  ingestion/       connector interface + file & synthetic connectors
  api/              FastAPI app and versioned routers
  cli/              Typer CLI
  system.py         orchestration facade wiring every engine together
tests/              45 pytest tests, including a full integration test
```

### Roadmap (not included in this release)

- **eBPF Sensor** — kernel-level process/socket/file collection agent
- **Distributed processing** — Kafka/NATS event streaming, worker pool, job orchestrator
- **Production graph database adapter** — Neo4j/JanusGraph behind the same `SecurityMemoryGraph` interface
- **Next.js frontend** — Timeline Explorer, Memory Graph Explorer, Incident Reconstruction Workspace, Counterfactual Lab, with English/Persian/Chinese localization and RTL/LTR support
- **Kubernetes/Helm deployment**, OIDC/OAuth2/RBAC/ABAC, and the remaining connectors (OpenTelemetry, journald/syslog, cloud audit, Kubernetes events)

---
<a name="فارسی"></a>
## 🇮🇷 فارسی

### این پروژه چیست

PHANTOM MEMORY رویدادهای پراکنده و کوتاه‌مدت امنیتی را به یک **حافظه‌ی
تاریخی، قابل جست‌وجو و قابل بازسازی** از رفتار امنیتی سیستم تبدیل می‌کند.
به‌جای این پرسش که «چه Alertی صادر شد؟»، این سیستم برای پاسخ به این سؤال
طراحی شده:

> *واقعاً چه اتفاقاتی، به چه ترتیبی رخ دادند؛ این رویدادها چگونه به هم
> متصل‌اند؛ اولین نقطه‌ی انحراف از رفتار عادی کجا بود؛ چه شواهدی این
> بازسازی را پشتیبانی می‌کنند؛ و آیا پیش‌تر چیزی مشابه این رخ داده است؟*

### آنچه در این نسخه پیاده‌سازی شده

این نسخه، **هسته‌ی Backend** پروژه است: مدل رویداد، حافظه‌ی رویداد تمپورال،
گراف حافظه‌ی امنیتی، موتور بازسازی Episode، تحلیل علّی/انحراف/اعتماد، لایه‌ی
بازیابی (Vector + Hybrid + شباهت تاریخی)، موتورهای حافظه‌ی دامنه (زنجیره‌ی
Process، Session شبکه، Authentication، Configuration)، فضای کاری تحقیق
(Case، Notebook، Bookmark)، یک API نسخه‌بندی‌شده (REST + WebSocket) و یک CLI
کامل — همگی واقعی، اجراشدنی و پوشش‌داده‌شده با ۴۵ تست خودکار موفق.

بخش‌هایی از چشم‌انداز کامل پروژه که در این نسخه **نیامده‌اند** — Sensor سطح
کرنل eBPF، لایه‌ی پردازش توزیع‌شده‌ی Kafka/NATS، استقرار Production یک گراف
دیتابیس، و رابط کاربری Next.js — به‌عمد کنار گذاشته شده‌اند تا هرچه در این
مخزن هست واقعی و کاملاً کاربردی باشد، نه نمایشی. به بخش «نقشه‌ی راه» در پایین
مراجعه کنید.

### نصب

نیازمند **Python 3.10 یا بالاتر**.

```bash
# ۱. ساخت و فعال‌سازی محیط مجازی (پیشنهادی)
python3 -m venv .venv
source .venv/bin/activate        # ویندوز: .venv\Scripts\activate

# ۲. نصب وابستگی‌ها
pip install -r requirements.txt

# ۳. (اختیاری) نصب خود پکیج، شامل دستور CLI به نام phantom-memory
pip install -e .
```

### اجرای تست‌ها

```bash
PYTHONPATH=. pytest tests/ -v
```

### اجرای API

```bash
PYTHONPATH=. uvicorn phantom_memory.api.main:app --reload --port 8000
```

سپس مستندات تعاملی OpenAPI را در آدرس زیر ببینید:
`http://localhost:8000/docs`

یا وضعیت سلامت خود پلتفرم را بررسی کنید:

```bash
curl http://localhost:8000/api/v1/health/self
```

### استفاده از CLI

```bash
# تولید داده‌ی مصنوعی و بنچمارک گرفتن از مسیر Ingestion تا بازسازی Episode
PYTHONPATH=. python -m phantom_memory.cli.main benchmark --event-count 2000

# Ingest کردن یک فایل از رویدادهای Canonical (آرایه‌ی JSON یا NDJSON)
PYTHONPATH=. python -m phantom_memory.cli.main ingest events.json

# بازسازی Episodeها از تمام داده‌های Ingest‌شده تا این لحظه
PYTHONPATH=. python -m phantom_memory.cli.main episode reconstruct

# فهرست Episodeها
PYTHONPATH=. python -m phantom_memory.cli.main episode list

# مشاهده‌ی کامل درخت دستورها
PYTHONPATH=. python -m phantom_memory.cli.main --help
```

### ساختار پروژه

```
phantom_memory/
  core/            مدل رویداد Canonical، Event Store، Clock، Dedup، Importance
  graph/           گراف حافظه‌ی امنیتی، موتور جست‌وجو، Entity Resolution
  temporal/        موتور وضعیت در لحظه‌ی مشخص، Snapshot، Diff، Replay
  episodes/        موتور بازسازی Episode، مدیریت چرخه‌ی حیات
  analysis/        فرضیه‌ی علّی، اولین انحراف، تناقض‌ها، اعتماد، کامل‌بودن شواهد
  retrieval/       ایندکس Vector، بازیابی Hybrid، شباهت تاریخی
  domain/          زنجیره‌ی Process، Session شبکه، Authentication، Configuration
  investigation/   مدیریت Case، Notebook، Bookmark شواهد
  ingestion/       اینترفیس Connector + Connectorهای File و Synthetic
  api/              اپلیکیشن FastAPI و Routerهای نسخه‌بندی‌شده
  cli/              CLI مبتنی بر Typer
  system.py         نقطه‌ی اتصال مرکزی همه‌ی موتورها
tests/              ۴۵ تست pytest، شامل یک تست یکپارچه‌ی کامل
```

### نقشه‌ی راه (در این نسخه نیامده)

- **Sensor سطح eBPF** — Agent جمع‌آوری سطح کرنل برای Process/Socket/File
- **پردازش توزیع‌شده** — استریم رویداد با Kafka/NATS، استخر Worker، Job Orchestrator
- **آداپتور گراف دیتابیس Production** — Neo4j/JanusGraph پشت همان اینترفیس `SecurityMemoryGraph`
- **رابط کاربری Next.js** — Timeline Explorer، Memory Graph Explorer، فضای کاری بازسازی Incident، آزمایشگاه Counterfactual، با بومی‌سازی انگلیسی/فارسی/چینی و پشتیبانی RTL/LTR
- **استقرار Kubernetes/Helm**، OIDC/OAuth2/RBAC/ABAC، و باقی Connectorها (OpenTelemetry، journald/syslog، Cloud Audit، رویدادهای Kubernetes)

---
<a name="中文"></a>
## 🇨🇳 中文

### 这是什么

PHANTOM MEMORY 将零散、短暂的安全事件转化为系统安全行为的**可搜索、可重建
的时序记忆**。它要回答的不是"触发了什么告警"，而是：

> *系统中究竟发生了什么、按什么顺序发生、这些事件之间如何关联、系统行为
> 从正常状态偏离的第一个时间点在哪里、有哪些证据支持这次重建、以及历史上
> 是否发生过类似的事情？*

### 本次发布已实现的内容

本仓库是项目的**后端核心**：规范事件模型、时序事件存储、安全记忆图谱、
事件序列（Episode）重建引擎、因果/偏离/置信度分析、检索层（向量检索 +
混合检索 + 历史相似度）、领域记忆引擎（进程谱系、网络会话、身份认证、
配置管理）、调查工作台（案件、笔记本、证据书签）、版本化的 REST/WebSocket
API，以及完整的命令行工具——全部为真实可运行的代码，并配有 45 个自动化
测试用例，全部通过。

完整产品愿景中的以下组件**未包含**在本次发布中——内核级 eBPF 探针、
Kafka/NATS 分布式处理层、生产级图数据库部署，以及 Next.js 前端界面——
均为刻意省略而非伪造实现，以确保本仓库中的一切都是真实、可运行的代码。
详见下方"路线图"部分。

### 安装

需要 **Python 3.10 及以上版本**。

```bash
# 1. 创建并激活虚拟环境（推荐）
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. 安装依赖
pip install -r requirements.txt

# 3.（可选）安装本包本身，包括 phantom-memory 命令行工具
pip install -e .
```

### 运行测试

```bash
PYTHONPATH=. pytest tests/ -v
```

### 运行 API

```bash
PYTHONPATH=. uvicorn phantom_memory.api.main:app --reload --port 8000
```

然后访问交互式 OpenAPI 文档：`http://localhost:8000/docs`

或检查平台自身健康状态：

```bash
curl http://localhost:8000/api/v1/health/self
```

### 使用命令行工具

```bash
# 生成合成数据并对"摄取 → 事件序列重建"流程进行基准测试
PYTHONPATH=. python -m phantom_memory.cli.main benchmark --event-count 2000

# 摄取一个规范事件文件（JSON 数组或 NDJSON）
PYTHONPATH=. python -m phantom_memory.cli.main ingest events.json

# 从目前已摄取的全部数据中重建事件序列
PYTHONPATH=. python -m phantom_memory.cli.main episode reconstruct

# 列出所有事件序列
PYTHONPATH=. python -m phantom_memory.cli.main episode list

# 查看完整命令树
PYTHONPATH=. python -m phantom_memory.cli.main --help
```

### 项目结构

```
phantom_memory/
  core/            规范事件模型、事件存储、时钟对齐、去重、重要性引擎
  graph/           安全记忆图谱、图搜索引擎、实体归并
  temporal/        时点状态重建、快照、差异比较、回放引擎
  episodes/        事件序列重建引擎、生命周期管理
  analysis/         因果假设、首次偏离检测、矛盾检测、置信度、证据完整性
  retrieval/       向量索引、混合检索、历史相似度
  domain/          进程谱系、网络会话、身份认证、配置管理
  investigation/   案件管理、调查笔记本、证据书签
  ingestion/       连接器接口 + 文件连接器与合成数据连接器
  api/              FastAPI 应用及版本化路由
  cli/              基于 Typer 的命令行工具
  system.py         将全部引擎串联起来的编排入口
tests/              45 个 pytest 测试，包含一个完整的端到端集成测试
```

### 路线图（本次发布未包含）

- **eBPF 探针** — 内核级进程/套接字/文件采集代理
- **分布式处理** — 基于 Kafka/NATS 的事件流、工作节点池、任务编排器
- **生产级图数据库适配器** — 在相同的 `SecurityMemoryGraph` 接口后接入 Neo4j/JanusGraph
- **Next.js 前端** — 时间线浏览器、记忆图谱浏览器、事件重建工作台、反事实推演实验室，支持英文/波斯文/中文本地化及 RTL/LTR 排版
- **Kubernetes/Helm 部署**、OIDC/OAuth2/RBAC/ABAC，以及其余连接器（OpenTelemetry、journald/syslog、云审计日志、Kubernetes 事件）

---

<p align="center"><sub>PHANTOM MEMORY — from "what alert fired?" to "what actually happened, and how do we know?"</sub></p>
