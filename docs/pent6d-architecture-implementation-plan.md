# Kế hoạch triển khai kiến trúc Pent6d

## 1. Mục tiêu

Tái cấu trúc Pent6d thành kiến trúc multi-agent phân cấp, có workflow rõ ràng và kiểm soát được:

- Supervisor deterministic quản lý vòng đời run, scope, quyền tool, budget và concurrency.
- Planner LLM lập hypothesis, attack graph và chọn task tiếp theo.
- Recon/Executor specialist thực hiện công việc chuyên môn.
- Critic/Validator kiểm chứng độc lập mọi kết quả.
- Chain & Impact Analyzer bắt buộc rà soát khả năng ghép lỗi và nâng impact.
- Shared typed blackboard lưu state, evidence và provenance theo project/run.
- UI hiển thị tiến trình theo phase, agent, task, evidence và finding.

Kiến trúc đích là **hierarchical, evidence-driven Planner–Executor–Critic Graph**. Không triển khai swarm tự do và không để một LLM duy nhất tự quyết định toàn bộ lifecycle.

## 2. Nguyên tắc thiết kế

1. **Recon-first:** không chạy vulnerability specialist trước khi recon được hoàn tất và snapshot thành công.
2. **Evidence-driven:** chỉ spawn specialist khi có tín hiệu từ recon, coverage gap, CVE/technology match hoặc dependency của attack chain.
3. **Supervisor an toàn:** các điều kiện scope, rate-limit, timeout, budget và quyền tool phải được kiểm tra bằng code.
4. **Planner thích ứng:** kế hoạch được cập nhật theo evidence mới, không dùng một checklist tĩnh duy nhất.
5. **Validation độc lập:** agent phát hiện không phải là bên duy nhất kết luận finding.
6. **Memory có cấu trúc:** lưu observation, hypothesis, task, attempt, evidence, finding và chain edge thay vì đẩy toàn bộ transcript vào prompt.
7. **Parallelism có kiểm soát:** chỉ chạy song song các task độc lập; task dùng chung session hoặc thay đổi trạng thái target phải tuần tự.
8. **Không mất provenance:** mọi observation và evidence phải gắn với project, run, agent, task, timestamp và artifact.
9. **Đóng run bắt buộc:** trước khi kết thúc phải hoàn thành coverage, validation, chain/impact và report reconciliation.
10. **Model-agnostic:** thiết kế không phụ thuộc OpenAI; DeepSeek vẫn có thể dùng làm Planner và specialist.

## 3. Workflow đích

```text
START
  -> Scope/ROE check
  -> Recon planning
  -> Recon execution
  -> Recon finalize + snapshot
  -> Hypothesis/attack-graph planning
  -> Specialist dispatch
  -> Local reflection + execution
  -> Evidence normalization
  -> Independent validation
  -> Global planner reflection
  -> Chain/impact analysis
  -> Coverage reconciliation
  -> Report/export
  -> Chat/retest
```

### 3.1 Các phase bắt buộc

| Phase | Kết quả bắt buộc |
|---|---|
| Scope | target, ROE, giới hạn network và credential |
| Recon | inventory endpoint, technology, subdomain, asset và artifact |
| Recon finalize | snapshot `recon.json`, marker hoàn tất và memory entry |
| Planning | hypothesis matrix và attack graph |
| Execution | task result, request/response hoặc artifact |
| Validation | verdict, confidence và reproduction status |
| Chain/impact | `validated_chain`, `impact_upgraded`, `no_chain` hoặc `ruled_out` |
| Coverage | trạng thái cho mọi surface/risk area |
| Reporting | findings, informational/thinking entries và overview nhất quán |

### 3.2 Các phase tùy chọn nhưng có điều kiện

- CVE research và PoC retrieval: chỉ khi technology/version có tín hiệu.
- Browser/Playwright: khi ứng dụng có flow động hoặc cần client-side state.
- Whitebox/source review: khi có source hoặc artifact hợp lệ.
- Deep exploit validation: khi finding có confidence đủ cao và nằm trong ROE.
- Web/RAG research: khi cần tài liệu, default credential hoặc PoC bổ sung.

## 4. Các lớp kiến trúc

### 4.1 Supervisor / Run Controller

Tạo module mới, ví dụ `strix/runtime/supervisor/`, chịu trách nhiệm:

- state machine của run;
- kiểm tra scope và quyền hành động;
- recon barrier;
- giới hạn số agent/task chạy đồng thời;
- rate-limit, timeout, retry và budget;
- cấp hoặc thu hồi tool capability;
- dừng task/run;
- chuyển phase;
- phát event cho UI.

Supervisor không tự suy luận payload và không tự thay thế Planner.

### 4.2 Planner / Attack Graph Manager

Tạo module điều phối chiến lược, có thể bắt đầu từ logic trong root agent rồi tách dần.

Planner phải:

- đọc recon snapshot và shared memory;
- xây dựng hypothesis matrix;
- tạo node/edge cho attack graph;
- chọn specialist và dispatch key;
- xác định prerequisite và fallback;
- cập nhật graph sau kết quả task;
- đánh dấu nhánh thất bại, bị loại hoặc cần kiểm chứng thêm;
- tạo task chain khi finding có khả năng nâng impact.

Planner không được trực tiếp bypass Supervisor để gọi tool có rủi ro cao.

### 4.3 Recon Collector Pool

Recon được chia thành các worker hợp lý, không tạo một agent cho từng endpoint/subdomain:

- asset/subdomain mapper;
- HTTP/technology fingerprint;
- endpoint/crawler mapper;
- JS/leak analyzer;
- screenshot/alive checker;
- source/config mapper;
- cloud/network exposure mapper.

Các worker ghi observation chuẩn hóa vào blackboard. Root không tự chạy recon tool; root theo dõi và tổng hợp kết quả.

### 4.4 Vulnerability Specialist Pool

Specialist được spawn theo evidence hoặc coverage gap:

- authentication/session;
- authorization/IDOR/BOLA;
- SQLi/NoSQLi/command injection;
- XSS/CSRF/SSTI/XXE;
- SSRF/path traversal/file upload;
- JWT/OAuth/MFA/bypass;
- API/GraphQL;
- CVE/PoC;
- browser/client-side;
- whitebox/local code.

Mỗi specialist phải có dispatch key, scope hẹp, input evidence rõ và output schema thống nhất.

### 4.5 Critic / Validator

Validator là lớp độc lập để:

- tái hiện claim;
- phân tích request/response và artifact;
- kiểm tra target identity;
- kiểm tra điều kiện authentication/session;
- loại false positive;
- gán confidence;
- xác định evidence còn thiếu;
- tạo `reported`, `ruled_out`, `informational` hoặc `thinking` theo bằng chứng.

Finding chỉ được coi là confirmed khi có evidence và validation record hợp lệ.

### 4.6 Chain & Impact Analyzer

Sau khi specialist và validator hoàn tất, Analyzer bắt buộc rà soát:

- finding nào có thể là prerequisite cho finding khác;
- credential/token có thể mở quyền mới không;
- low-impact issue có thể nâng thành impact cao hơn không;
- chain có được tái hiện đầy đủ không;
- bước nào chỉ là giả thuyết;
- chain có nằm trong scope không.

Kết quả phải được ghi vào chain ledger, không chỉ nằm trong text report.

## 5. Shared typed blackboard

Blackboard nên gồm hai lớp:

1. **Append-only event log:** lịch sử không ghi đè, có provenance.
2. **Materialized state:** view nhỏ gọn để Planner và UI truy vấn.

Các entity chính:

```text
Project
Run
ReconObservation
TechnologyFingerprint
Endpoint
Credential
Session
Hypothesis
Task
Attempt
Evidence
Finding
ChainEdge
CoverageEntry
Decision
Artifact
```

Quyền đề xuất:

| Actor | Quyền chính |
|---|---|
| Supervisor | chuyển state, cấp capability, dừng/retry |
| Planner | đọc evidence, ghi plan/hypothesis/task |
| Recon worker | ghi observation/artifact |
| Specialist | ghi attempt/evidence/claim |
| Validator | ghi verdict/confidence/reproduction |
| Chain analyzer | ghi chain edge/impact decision |
| Reporter | chỉ đọc state đã reconcile |

Mỗi project phải tách dữ liệu khỏi project khác. Mỗi run phải có namespace riêng nhưng có thể tham chiếu knowledge đã được project chấp nhận.

## 6. Reflection và retry

### 6.1 Local reflection

Áp dụng trong specialist:

```text
Generate action
  -> Pre-action check
  -> Execute
  -> Parse response
  -> Compare expected/actual
  -> Mutate payload hoặc đổi phương án
  -> Retry hoặc stop
```

Local reflection phải có giới hạn số vòng, giới hạn request và lý do dừng.

### 6.2 Global reflection

Gọi sau khi specialist hoàn tất hoặc khi có evidence quan trọng:

1. Planner đọc task result và memory summary.
2. Validator xác định task đã đủ bằng chứng chưa.
3. Planner cập nhật attack graph.
4. Supervisor quyết định dispatch task kế tiếp.

Không gọi Planner sau từng HTTP request để tránh tăng token và chi phí quá mức.

## 7. Chính sách spawn và concurrency

### Spawn specialist khi

- có technology/version match;
- có endpoint hoặc response signal phù hợp;
- có credential/session cần kiểm tra;
- có coverage gap bắt buộc;
- có finding cần validator độc lập;
- có prerequisite cho chain.

### Không spawn khi

- chỉ có tín hiệu chung chung không gắn target;
- task trùng dispatch key đang chạy hoặc đã hoàn tất;
- không có evidence mới;
- task vượt scope hoặc risk policy.

### Chạy song song

- passive recon;
- fingerprint độc lập;
- endpoint classification;
- specialist không dùng chung session và không mutate state.

### Chạy tuần tự

- authentication/session;
- task dùng chung credential;
- state mutation;
- exploit chain;
- CVE PoC có tác động;
- privilege escalation.

## 8. Kế hoạch triển khai theo giai đoạn

### Giai đoạn 0 — Baseline và contract

**Mục tiêu:** đóng băng hành vi hiện tại và thống nhất schema.

- lập inventory module hiện tại;
- định nghĩa `RunState`, `Task`, `Evidence`, `Finding`, `ChainEdge`;
- thống nhất status và transition;
- thêm correlation ID cho project/run/agent/task;
- viết test cho recon barrier và finish gate hiện có.

**Tiêu chí hoàn thành:** không thay đổi hành vi scan hiện tại; mọi event quan trọng có ID và run scope.

### Giai đoạn 1 — Tách Supervisor

**Mục tiêu:** đưa lifecycle và safety gate ra khỏi prompt.

- tạo `RunSupervisor`;
- chuyển scope, phase, timeout, retry, budget và concurrency vào runtime;
- giữ root prompt chỉ cho planning/orchestration;
- phát event `run_started`, `phase_changed`, `task_started`, `task_finished`, `run_failed`, `run_completed`.

**Tiêu chí hoàn thành:** Planner không thể bypass scope hoặc spawn specialist khi recon chưa finalized.

### Giai đoạn 2 — Typed blackboard

**Mục tiêu:** chuẩn hóa shared memory.

- tạo event tables và materialized views;
- lưu evidence/artifact theo entity, không lưu transcript lớn;
- thêm provenance và dedup key;
- migrate dữ liệu `recon.json`, coverage, reports và chain ledger vào cùng schema;
- giữ backward compatibility với các tool memory hiện tại.

**Tiêu chí hoàn thành:** agent mới có thể đọc đủ recon/evidence mà không cần copy toàn bộ conversation.

### Giai đoạn 3 — Planner và attack graph

**Mục tiêu:** thay checklist tuyến tính bằng graph có dependency.

- tạo `HypothesisMatrix`;
- tạo `AttackGraph` và graph persistence;
- viết planner prompt có input/output JSON schema;
- thêm policy chọn specialist;
- chống duplicate task bằng dispatch key và graph identity.

**Tiêu chí hoàn thành:** planner tạo được task có prerequisite, risk, evidence requirement và next action.

### Giai đoạn 4 — Specialist contract và dispatch

**Mục tiêu:** chuẩn hóa execution.

- mỗi specialist nhận task envelope;
- output bắt buộc gồm action, result, evidence, confidence và open items;
- giới hạn capability theo role;
- thêm bounded parallel scheduler;
- bảo đảm stateful task được serialize.

**Tiêu chí hoàn thành:** specialist không tự ý mở rộng scope hoặc tạo finding thiếu evidence.

### Giai đoạn 5 — Critic, validation và reflection

**Mục tiêu:** giảm false positive và hỗ trợ exploit nhiều bước.

- thêm local response-driven retry;
- thêm independent validator;
- thêm global planner reflection;
- đặt retry/request/iteration budget;
- ghi rõ lý do `ruled_out`, `informational`, `thinking` hoặc `needs_follow_up`.

**Tiêu chí hoàn thành:** mỗi finding có validation record; mỗi retry có reason và termination status.

### Giai đoạn 6 — Chain và impact

**Mục tiêu:** bắt buộc xử lý chuỗi tấn công.

- tạo chain graph;
- tạo chain review task tự động sau specialist batch;
- kiểm tra credential/token/privilege transitions;
- cập nhật severity/impact bằng `update_vulnerability_report` khi có evidence mới;
- không biến giả thuyết thành confirmed finding.

**Tiêu chí hoàn thành:** finish bị chặn nếu finding/observation bắt buộc chưa có chain verdict.

### Giai đoạn 7 — UI và observability

**Mục tiêu:** người dùng theo dõi được workflow thật.

- hiển thị phase hiện tại;
- hiển thị Planner decision và task graph;
- hiển thị agent đang chạy, waiting, retrying, failed;
- hiển thị recon snapshot và shared memory summary;
- hiển thị evidence timeline;
- cho phép dừng một task/run;
- hỗ trợ chat theo từng run;
- hiển thị chain và coverage map.

**Tiêu chí hoàn thành:** người dùng phân biệt được “đang suy luận”, “đang gọi tool”, “đang retry”, “đã validate” và “đã kết thúc”.

### Giai đoạn 8 — Đánh giá và tối ưu

**Mục tiêu:** đo kiến trúc bằng số liệu, không chỉ cảm nhận.

Theo dõi:

- recon completion rate;
- specialist spawn precision;
- duplicate task rate;
- finding validation rate;
- false-positive rate;
- chain completion rate;
- coverage closure rate;
- token/cache ratio;
- cost per confirmed finding;
- time to first finding;
- time to complete run.

## 9. Chiến lược migration an toàn

Không thay đổi toàn bộ trong một lần.

1. Giữ các tool hiện tại và bọc chúng bằng task envelope.
2. Chuyển Supervisor vào runtime trước khi thay đổi prompt lớn.
3. Chạy Planner mới ở chế độ shadow để so sánh task với root hiện tại.
4. Bật từng specialist group theo feature flag.
5. Cho phép fallback về workflow cũ khi graph hoặc memory lỗi.
6. Chỉ bật chain/impact bắt buộc sau khi ledger đã có migration ổn định.
7. Chạy regression trên các run đã lưu trước khi bật mặc định.

## 10. Rủi ro và biện pháp kiểm soát

| Rủi ro | Kiểm soát |
|---|---|
| Planner spawn quá nhiều agent | dispatch key, budget, concurrency cap |
| Agent lặp vô hạn | task/attempt/iteration limit |
| Memory phình lớn | event log + compact materialized view |
| Mất context quan trọng | typed evidence và pinned facts |
| False positive | validator độc lập và reproduction |
| Chain suy diễn quá mức | chain edge phải có evidence |
| Model suy luận sai scope | Supervisor deterministic gate |
| Parallel task gây xung đột session | session lock và task dependency |
| UI hiển thị trạng thái sai | event-sourced run state |
| Model provider thay đổi schema | adapter và output validation |

## 11. Definition of Done

Kiến trúc mới được coi là hoàn thành khi:

- Supervisor và Planner đã tách thành hai trách nhiệm rõ ràng;
- recon luôn được finalize trước specialist execution;
- mọi task có trạng thái, dependency và provenance;
- specialist được spawn theo evidence/coverage/chain policy;
- shared memory có schema theo project/run;
- finding bắt buộc qua validation;
- chain/impact được kiểm tra trước khi finish;
- retry và reflection có giới hạn;
- UI hiển thị đầy đủ phase, agent, task, evidence và failure;
- báo cáo có thể truy ngược từ finding về task, request/response và artifact;
- regression, unit test và integration test đều pass;
- có fallback và migration path khi một module mới lỗi.

## 12. Thứ tự ưu tiên đề xuất

Nếu phải triển khai từng phần, thứ tự nên là:

1. Supervisor runtime và state machine.
2. Typed shared blackboard.
3. Attack graph và Planner output schema.
4. Specialist dispatch/concurrency policy.
5. Independent validator và reflection.
6. Chain/impact analyzer.
7. UI workflow/observability.
8. Benchmark, cost optimization và model-specific tuning.

Đây là thứ tự ít rủi ro nhất vì nó củng cố control plane và state trước, sau đó mới tăng mức độ tự chủ của Planner và specialist.

## 13. Trạng thái triển khai

Đợt triển khai đầu tiên đã hoàn thành:

- [x] `RunSupervisor` với state machine và file `.state/supervisor.json`.
- [x] Runner phát lifecycle phase cho sandbox, agent setup và agent loop.
- [x] `finalize_recon` ghi phase `recon_finalized` vào supervisor state.
- [x] `finish_scan` ghi trạng thái terminal `completed`.
- [x] Shared memory hỗ trợ typed kinds cho task, attempt, evidence, finding,
  chain edge, coverage, artifact và session.
- [x] Shared memory có `metadata` JSON để liên kết task/finding/dependency;
  database cũ được migrate lazy.
- [x] Attack graph persistence theo run với dependency, status, retry count và
  stable dispatch key.
- [x] Agent tools `create_attack_task`, `update_attack_task` và
  `list_attack_tasks` đã được đăng ký cho Planner/specialist.
- [x] Viewer có `/api/workflow` và workflow graph theo lane Scope, Recon,
  Planning, Execution, Validation, Chain/Impact và Reporting; node hiển thị
  type, status, risk, attempts, source nodes, evidence IDs và generated-by.
- [x] Regression tests cho supervisor, attack graph, shared memory, recon và
  agent coordination đã pass.
- [x] Checklist phương pháp theo run được tạo từ các vulnerability/protocol
  skill pack, lưu tại `state/checklist.json` và mirror ở artifact root.
- [x] Checklist có evidence gate cho `pass`/`fail`, trạng thái trung gian
  `partial`/`blocked`/`needs_validation`, kiểm tra integrity và export JSON/
  Markdown.
- [x] `finish_scan` chặn kết thúc khi checklist còn mở; specialist dispatch
  trên run checklist-enabled phải khai báo `checklist_codes` để planner giao
  ownership rõ ràng.
- [x] Khi specialist gọi `agent_finish`, task tương ứng được đóng trong
  attack graph và tự sinh task `validator` rồi `chain_reviewer` theo
  dependency; các task này idempotent theo `dispatch_key`.
- [x] Root có `dispatch_ready_tasks` để chạy các follow-up đã ready, giữ giới
  hạn concurrency và bind agent runtime vào graph task.

Các phần tiếp theo chưa bật mặc định gồm scheduler đọc attack graph, independent
validator orchestration, reflection loop và UI graph view. Chúng sẽ được triển
khai sau khi các state contract hiện tại được giữ ổn định qua thêm một vòng
integration test.
