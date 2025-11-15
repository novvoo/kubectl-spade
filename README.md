# kubectl-spade

`kubectl-spade` 是一个 kubectl 插件，用于在 Kubernetes 节点上使用 `ctr` 命令拉取和标记容器镜像。它通过创建一个特权调试 Pod 来执行容器运行时操作，并提供详细的日志分析和故障排除建议。

## 功能特性

- **节点级镜像拉取**: 在指定的 Kubernetes 节点上拉取容器镜像
- **镜像标记**: 将拉取的镜像标记为指定的目标镜像名
- **认证支持**: 支持通过 Kubernetes Secret 提供镜像仓库认证信息
- **智能日志分析**: 自动解析操作日志并提供故障排除建议
- **Dry-run 模式**: 支持预览模式，仅显示将要执行的操作而不实际执行
- **自动清理**: 操作完成后自动清理创建的调试 Pod

## 安装

### 作为 kubectl 插件安装

1. 将 `kubectl-spade` 二进制文件放置到 PATH 中的任意位置，并确保文件名格式为 `kubectl-spade`

```bash
# 下载或构建二进制文件
# 将二进制文件移动到 PATH 中的位置
sudo mv kubectl-spade /usr/local/bin/
```

2. 验证安装

```bash
kubectl spade --help
```

### 从源码构建

```bash
git clone <repository-url>
cd kubectl-spade
go build -o kubectl-spade
sudo mv kubectl-spade /usr/local/bin/
```

## 使用方法

### 基本用法

```bash
kubectl spade --pod <POD_NAME> --image <SOURCE_IMAGE> [OPTIONS]
```

### 参数说明

- `--pod`: 目标 Pod 名称（必需）
- `--namespace`: Pod 所在的命名空间（默认: default）
- `--image`: 要在目标节点拉取的源镜像（必需）
- `--container-image`: 当 Pod 有多个容器时，指定要替换的容器镜像（容器名、索引或部分镜像名）
- `--image-pull-secret`: 用于拉取镜像的 Secret 名称（可选）
- `--debug-image`: 用于调试的镜像（默认: mcr.microsoft.com/cbl-mariner/busybox:2.0）
- `--timeout`: 超时时间，单位秒（默认: 180）
- `--dry-run`: 仅预览，不实际执行操作
- `--kubeconfig`: kubeconfig 文件路径（可选）

### 示例

1. **基本镜像拉取**

```bash
kubectl spade --pod my-pod --image registry.example.com/my-app:v1.0.0
```

2. **使用认证 Secret**

```bash
kubectl spade --pod my-pod --image private-registry.com/app:v2.0.0 --image-pull-secret my-registry-secret
```

3. **指定命名空间和容器镜像**

```bash
kubectl spade --pod my-pod --namespace production --image new-image:v1.0.0 --container-image app-container-image
```

4. **支持 Init Containers**

```bash
# 指定 init container 的索引（init containers 在列表前面）
kubectl spade --pod my-pod --image new-image:v1.0.0 --container-image 0

# 指定 init container 的名称
kubectl spade --pod my-pod --image new-image:v1.0.0 --container-image init-container-image

# 通过镜像名的一部分匹配容器
kubectl spade --pod my-pod --image new-image:v1.0.0 --container-image "nginx"
```

5. **预览模式**

```bash
kubectl spade --pod my-pod --image my-image:v1.0.0 --dry-run
```

## 工作原理

1. **获取目标信息**: 根据指定的 Pod 获取所在节点和目标镜像信息
2. **构建执行脚本**: 生成在调试 Pod 中执行的 shell 脚本
3. **创建调试 Pod**: 在目标节点上创建特权 Pod，挂载主机路径以访问 containerd
4. **执行操作**: 在调试 Pod 中运行 `ctr` 命令拉取和标记镜像
5. **日志分析**: 收集操作日志并进行智能分析，提供故障排除建议
6. **清理资源**: 自动删除调试 Pod

## 支持的调试镜像

默认使用的调试镜像需要支持以下工具：
- `sh` 或 `bash`
- `chroot`
- `base64`
- `sed`
- `grep`
- `ctr` (containerd CLI)

推荐的调试镜像：
- `mcr.microsoft.com/cbl-mariner/busybox:2.0` (默认)
- 其他包含必要工具的 Linux 镜像

## 注意事项

- 该插件需要创建特权 Pod，需要相应的 Kubernetes 权限
- 调试 Pod 会挂载主机的 `/` 和 `/run` 目录
- 确保目标节点上安装了 `ctr` 命令
- 使用私有镜像仓库时，确保 Secret 配置正确

## 故障排除

插件会自动分析操作日志并提供以下类型的建议：

- **认证问题**: 当遇到认证失败时的解决建议
- **网络问题**: 当遇到连接或DNS问题时的解决建议
- **权限问题**: 当遇到权限或TLS证书问题时的解决建议
- **镜像问题**: 当遇到镜像名称或格式问题时的解决建议

## 许可证

[添加许可证信息]
