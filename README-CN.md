# VMware Policy

VMware MCP 技能家族的统一审计日志、策略执行与输入消毒基础设施层。

## 安装

```bash
pip install vmware-policy
```

## 使用方法

```python
from vmware_policy import vmware_tool

@vmware_tool(risk_level="high", sensitive_params=["password"])
def delete_segment(name: str, env: str = "") -> dict:
    ...
```

## CLI 命令

```bash
vmware-audit log --last 20
vmware-audit log --status denied --since 2026-03-28
vmware-audit stats --days 7
```

## 核心组件

| 组件 | 说明 |
|------|------|
| `@vmware_tool` | 装饰器 -- 所有 VMware MCP 工具的强制包装器，负责策略前置检查 + 执行 + 审计日志记录 |
| `AuditEngine` | 基于 SQLite WAL 的追加式审计日志引擎，支持日志轮转（100MB 阈值，保留 5 个归档） |
| `PolicyEngine` | 基于 YAML 的规则引擎，支持拒绝规则、维护窗口、变更限制，文件变更时自动热加载 |
| `sanitize()` | 提示注入防御 -- 截断至 500 字符 + 清理 C0/C1 控制字符 |
| `vmware-audit` | Typer CLI -- 查询审计日志、导出 JSON、统计分析 |

## 架构

```
AI Agent -> vmware-pilot（按需编排）-> @vmware_tool 前置检查 -> skill 操作 -> 后置审计 -> ~/.vmware/audit.db
```

vmware-policy 是所有 VMware 技能的**强制依赖**，提供：

- **审计日志**：所有 156+ MCP 工具的操作记录写入统一数据库 `~/.vmware/audit.db`
- **策略引擎**：deny 规则、维护窗口、变更限制，热加载无需重启
- **输入消毒**：所有来自 vSphere/NSX/Aria API 的文本经过 `sanitize()` 处理
- **AI Agent 检测**：自动识别 Claude、Codex、Ollama、DeerFlow 等调用方

## 策略规则配置

将默认规则复制到 `~/.vmware/rules.yaml` 并自定义：

```yaml
# 拒绝规则 -- 阻止特定操作
deny:
  - name: no-delete-in-prod
    operations: ["delete_*", "cluster_delete"]
    environments: ["production"]
    reason: "生产环境禁止破坏性操作"

# 维护窗口 -- 高/危险操作仅在窗口内允许
maintenance_window:
  start: "22:00"
  end: "06:00"

# 变更限制 -- 参数阈值检查
change_limits:
  max_cpu_change_pct: 20
  max_memory_change_pct: 50
```

规则修改后自动热加载，无需重启任何服务。

## 风险等级

| 等级 | 需要确认 | 示例 |
|------|:--------:|------|
| `low` | 否 | list、get、info、status |
| `medium` | 否 | reconfigure、update |
| `high` | 是 | power off、migrate、snapshot revert |
| `critical` | 是 + 生产审批 | delete VM、delete cluster |

## VMware 技能家族

| 技能 | 定位 | 安装命令 |
|------|------|---------|
| **vmware-aiops** | VM 生命周期 + 部署 + Guest Ops | `uv tool install vmware-aiops` |
| **vmware-monitor** | 只读监控 | `uv tool install vmware-monitor` |
| **vmware-storage** | 存储管理（iSCSI + vSAN） | `uv tool install vmware-storage` |
| **vmware-vks** | Tanzu Kubernetes | `uv tool install vmware-vks` |
| **vmware-nsx** | NSX 网络管理 | `uv tool install vmware-nsx-mgmt` |
| **vmware-nsx-security** | NSX 安全（DFW + 安全组） | `uv tool install vmware-nsx-security` |
| **vmware-aria** | Aria Ops 指标/告警/容量 | `uv tool install vmware-aria` |
| **vmware-avi** | AVI/ALB 负载均衡 | `uv tool install vmware-avi` |
| **vmware-pilot** | 多步骤工作流编排 | `uv tool install vmware-pilot` |
| **vmware-policy** | 审计 + 策略（本包） | `uv tool install vmware-policy` |

## 安全

- 密码通过 `sensitive_params` 在审计日志中脱敏为 `***`
- 审计数据库仅本地存储（`~/.vmware/audit.db`），无网络暴露
- `sanitize()` 防止通过 API 响应文本进行提示注入
- 策略旁路模式（`VMWARE_POLICY_DISABLED=1`）仍记录审计日志

## 开发

```bash
git clone https://github.com/zw008/VMware-Policy.git
cd VMware-Policy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest --cov=vmware_policy
```

## 许可证

MIT
