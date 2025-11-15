// main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	var (
		podName        string
		namespace      string
		kubeconf       string
		sourceImage    string
		timeoutSeconds int
		secretName     string
		containerSel   string
		debugImage     string
		dryRun         bool
	)

	flag.StringVar(&podName, "pod", "", "目标 Pod 名（必需）")
	flag.StringVar(&namespace, "namespace", "default", "命名空间（默认 default）")
	flag.StringVar(&sourceImage, "image", "", "要在目标节点 pull 的源镜像（必需）")
	flag.IntVar(&timeoutSeconds, "timeout", 180, "超时时间（秒）")
	flag.StringVar(&secretName, "image-pull-secret", "", "（可选）imagePullSecret 名（类型建议 kubernetes.io/dockerconfigjson），以只读 volume 挂载到容器内并在容器内即时清理")
	flag.StringVar(&containerSel, "container-image", "", "当 Pod 有多个容器时，指定要替换的容器镜像（容器名、索引或部分镜像名）")
	flag.StringVar(&debugImage, "debug-image", "mcr.microsoft.com/cbl-mariner/busybox:2.0", "用于调试的镜像（须支持 sh/chroot/base64/sed/grep）")
	flag.BoolVar(&dryRun, "dry-run", false, "仅打印将要执行的 shell 脚本和 Pod spec（YAML），不在集群中创建资源")

	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconf, "kubeconfig", filepath.Join(home, ".kube", "config"), "kubeconfig 路径（可选）")
	} else {
		flag.StringVar(&kubeconf, "kubeconfig", "", "kubeconfig 路径（可选）")
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "kubectl-spade - 在节点上用 ctr pull/tag（secret 做只读 volume，日志解析并给出建议）\n\n")
		fmt.Fprintf(os.Stderr, "用法:\n  kubectl spade --pod POD_NAME --image SOURCE_IMAGE [options]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if podName == "" || sourceImage == "" {
		flag.Usage()
		os.Exit(2)
	}

	// kube client
	config, err := clientcmd.BuildConfigFromFlags("", kubeconf)
	if err != nil {
		exitf("读取 kubeconfig 失败: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		exitf("创建 k8s client 失败: %v", err)
	}

	ctx := context.Background()

	// 1) 找 pod，取 node 与目标 image（targetImage）
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			exitf("未找到 Pod %s/%s", namespace, podName)
		}
		exitf("获取 Pod 失败: %v", err)
	}
	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		exitf("Pod %s/%s 尚未被调度到节点（nodeName 为空）", namespace, podName)
	}
	fmt.Printf("目标 Pod: %s/%s  在节点: %s\n", namespace, podName, nodeName)

	targetImage, err := pickTargetImage(pod, containerSel)
	if err != nil {
		exitf("选择目标容器镜像失败: %v", err)
	}
	fmt.Printf("source image: %s -> target image (pod container): %s\n", sourceImage, targetImage)

	// 2) 构造脚本（增强）
	useSecret := secretName != ""
	cmd := buildShellCmdEnhanced(sourceImage, targetImage, useSecret)

	// 3) 构造 Pod spec（带或不带 secret volume）
	debugPodName := fmt.Sprintf("spade-ctr-%d", time.Now().Unix())
	var debugPod *corev1.Pod
	if useSecret {
		debugPod = buildCtrDebugPodWithSecretVolume(debugPodName, namespace, nodeName, debugImage, cmd, secretName)
	} else {
		debugPod = buildCtrDebugPodNoCred(debugPodName, namespace, nodeName, debugImage, cmd)
	}

	// 4) 如果 dry-run，打印脚本和 pod spec YAML 并退出（不创建）
	if dryRun {
		fmt.Println("---- DRY-RUN: script to run on debug pod ----")
		fmt.Println(cmd)
		fmt.Println("---- DRY-RUN: debug pod spec (YAML) ----")
		// marshal to JSON then convert to YAML for reliable k8s object serialization
		jb, _ := json.Marshal(debugPod)
		yb, err := yaml.JSONToYAML(jb)
		if err != nil {
			// fallback: try direct YAML marshal (less reliable for k8s types)
			fallback, _ := yaml.Marshal(debugPod)
			fmt.Println(string(fallback))
		} else {
			fmt.Println(string(yb))
		}
		fmt.Println("---- DRY-RUN END ----")
		return
	}

	// 5) 创建 debug pod
	created, err := clientset.CoreV1().Pods(namespace).Create(ctx, debugPod, metav1.CreateOptions{})
	if err != nil {
		exitf("创建 debug Pod 失败: %v", err)
	}
	fmt.Printf("已创建 debug Pod %s/%s 在节点 %s 执行 ctr 操作\n", namespace, created.Name, nodeName)

	// 6) 等待 pod 完成或超时
	waitTimeout := time.Duration(timeoutSeconds) * time.Second
	podClient := clientset.CoreV1().Pods(namespace)
	start := time.Now()
	done := false
	for !done && time.Since(start) < waitTimeout {
		p, err := podClient.Get(ctx, created.Name, metav1.GetOptions{})
		if err == nil {
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				done = true
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	if !done {
		fmt.Fprintf(os.Stderr, "等待 debug Pod 超时（%s）\n", waitTimeout)
	}

	// 7) 读取日志并输出（包含 PULL_RC/TAG_RC/EXIT 等）
	req := podClient.GetLogs(created.Name, &corev1.PodLogOptions{})
	logStream, err := req.Stream(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取 debug Pod 日志失败: %v\n", err)
	} else {
		fmt.Println("---- debug pod logs start ----")
		scanner := bufio.NewScanner(logStream)
		var logLines []string
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
			logLines = append(logLines, line)
		}
		_ = logStream.Close()
		fmt.Println("---- debug pod logs end ----")

		// 解析日志并给出建议
		analyzeLogsAndSuggest(logLines, sourceImage, targetImage, useSecret)
	}

	// 8) 删除 debug pod（尽量强制）
	propagation := metav1.DeletePropagationForeground
	_ = podClient.Delete(ctx, created.Name, metav1.DeleteOptions{PropagationPolicy: &propagation})
	fmt.Printf("已请求删除 debug Pod %s/%s\n", namespace, created.Name)

	fmt.Println("完成。")
}

// ---------- shell script builder（增强） ----------
func buildShellCmdEnhanced(source, target string, useSecret bool) string {
	var sb strings.Builder

	// header
	sb.WriteString("set -e\n")
	if useSecret {
		sb.WriteString("echo '(secret volume mounted)'; ")
		sb.WriteString("if [ -f /tmp/creds/config.json ]; then ")
		sb.WriteString("auth=$(sed -n 's/.*\"auth\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /tmp/creds/config.json | head -n1); ")
		sb.WriteString("if [ -n \"$auth\" ]; then ")
		sb.WriteString("creds=$(echo \"$auth\" | base64 -d 2>/dev/null) || creds=\"\"; echo \"(creds extracted from auth)\"; ")
		sb.WriteString("else ")
		sb.WriteString("user=$(sed -n 's/.*\"username\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /tmp/creds/config.json | head -n1); ")
		sb.WriteString("pass=$(sed -n 's/.*\"password\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /tmp/creds/config.json | head -n1); ")
		sb.WriteString("if [ -n \"$user\" ] && [ -n \"$pass\" ]; then creds=\"$user:$pass\"; echo \"(creds assembled from username/password)\"; else ")
		sb.WriteString("firstauth=$(sed -n 's/.*\"auth\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /tmp/creds/config.json | head -n1); ")
		sb.WriteString("if [ -n \"$firstauth\" ] && [ -z \"$creds\" ]; then creds=$(echo \"$firstauth\" | base64 -d 2>/dev/null) || creds=\"\"; echo \"(creds extracted from fallback auth)\"; fi; ")
		sb.WriteString("fi; fi; ")
		sb.WriteString("else echo '(no /tmp/creds/config.json)'; fi; ")
	} else {
		sb.WriteString("echo '(no secret provided)'; ")
	}

	// Pull
	sb.WriteString("echo '---- BEGIN_PULL ----'; ")
	if useSecret {
		sb.WriteString("if [ -n \"$creds\" ]; then echo '(using creds)'; chroot /host ctr -n k8s.io images pull --user \"$creds\" '" + escapeSingle(source) + "' > /tmp/pull_out 2>&1; rc=$?; else echo '(no creds available or decode failed)'; chroot /host ctr -n k8s.io images pull '" + escapeSingle(source) + "' > /tmp/pull_out 2>&1; rc=$?; fi; ")
	} else {
		sb.WriteString("chroot /host ctr -n k8s.io images pull '" + escapeSingle(source) + "' > /tmp/pull_out 2>&1; rc=$?; ")
	}
	sb.WriteString("echo \"PULL_RC:$rc\"; cat /tmp/pull_out || true; echo '---- END_PULL ----'; ")

	// Tag
	sb.WriteString("echo '---- BEGIN_TAG ----'; ")
	sb.WriteString("chroot /host ctr -n k8s.io images tag '" + escapeSingle(source) + "' '" + escapeSingle(target) + "' > /tmp/tag_out 2>&1; trc=$?; ")
	sb.WriteString("echo \"TAG_RC:$trc\"; cat /tmp/tag_out || true; echo '---- END_TAG ----'; ")

	// cleanup secret file in container mount
	sb.WriteString("if [ -f /tmp/creds/config.json ]; then if command -v shred >/dev/null 2>&1; then shred -u /tmp/creds/config.json || rm -f /tmp/creds/config.json; else rm -f /tmp/creds/config.json; fi; fi; ")

	// exit
	sb.WriteString("if [ ${rc:-1} -ne 0 ] || [ ${trc:-1} -ne 0 ]; then echo \"EXIT:1\"; else echo \"EXIT:0\"; fi; sleep 2;")

	return sb.String()
}

// ---------- Pod builders ----------
func buildCtrDebugPodWithSecretVolume(name, namespace, nodeName, debugImage, cmd, secretName string) *corev1.Pod {
	priv := true
	term := false
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app":   "kubectl-spade",
				"spade": name,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                      nodeName,
			HostPID:                       true,
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: int64Ptr(5),
			Containers: []corev1.Container{
				{
					Name:            "ctr-runner",
					Image:           debugImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sh", "-c", cmd},
					SecurityContext: &corev1.SecurityContext{Privileged: &priv},
					Stdin:           term,
					TTY:             term,
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host-root", MountPath: "/host"},
						{Name: "host-run", MountPath: "/run"},
						{Name: "pull-creds", MountPath: "/tmp/creds", ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "host-root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/", Type: nil}}},
				{Name: "host-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run", Type: nil}}},
				{
					Name: "pull-creds",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretName,
							Items: []corev1.KeyToPath{
								{Key: ".dockerconfigjson", Path: "config.json"},
							},
						},
					},
				},
			},
		},
	}
	return p
}

func buildCtrDebugPodNoCred(name, namespace, nodeName, debugImage, cmd string) *corev1.Pod {
	priv := true
	term := false
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app":   "kubectl-spade",
				"spade": name,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                      nodeName,
			HostPID:                       true,
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: int64Ptr(5),
			Containers: []corev1.Container{
				{
					Name:            "ctr-runner",
					Image:           debugImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sh", "-c", cmd},
					SecurityContext: &corev1.SecurityContext{Privileged: &priv},
					Stdin:           term,
					TTY:             term,
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host-root", MountPath: "/host"},
						{Name: "host-run", MountPath: "/run"},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "host-root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/", Type: nil}}},
				{Name: "host-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run", Type: nil}}},
			},
		},
	}
	return p
}

// ---------- helpers ----------
func pickTargetImage(pod *corev1.Pod, containerSel string) (string, error) {
	// 合并普通容器和 init 容器
	allContainers := make([]corev1.Container, 0)
	allContainers = append(allContainers, pod.Spec.InitContainers...)
	allContainers = append(allContainers, pod.Spec.Containers...)

	if len(allContainers) == 0 {
		return "", errors.New("pod 没有容器（包括 init containers）")
	}
	if len(allContainers) == 1 {
		return allContainers[0].Image, nil
	}
	if containerSel == "" {
		var b strings.Builder
		b.WriteString("pod 有多个容器，请通过 --container-image 指定（容器名、索引或部分镜像名）：\n")
		for i, c := range allContainers {
			containerType := "container"
			if i < len(pod.Spec.InitContainers) {
				containerType = "init-container"
			}
			b.WriteString(fmt.Sprintf("  %s[%d]: %s (image=%s)\n", containerType, i, c.Name, c.Image))
		}
		return "", errors.New(b.String())
	}
	if idx, err := strconv.Atoi(containerSel); err == nil {
		if idx < 0 || idx >= len(allContainers) {
			return "", fmt.Errorf("容器索引超出范围: %d（总容器数: %d）", idx, len(allContainers))
		}
		return allContainers[idx].Image, nil
	}
	for _, c := range allContainers {
		if c.Name == containerSel {
			return c.Image, nil
		}
	}
	for _, c := range allContainers {
		if strings.Contains(c.Image, containerSel) {
			return c.Image, nil
		}
	}
	return "", fmt.Errorf("找不到匹配的容器 '%s'（请传容器名、索引或部分镜像名）", containerSel)
}

func escapeSingle(s string) string {
	return strings.ReplaceAll(s, "'", "'\"'\"'")
}

func int64Ptr(i int64) *int64 { return &i }

func exitf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

// ---------- log analysis & suggestions ----------
func analyzeLogsAndSuggest(lines []string, source, target string, usedSecret bool) {
	var pullRC, tagRC, exitRC *int
	var pullOutput []string
	var tagOutput []string
	var interesting []string

	inPull := false
	inTag := false
	for _, l := range lines {
		if strings.Contains(l, "BEGIN_PULL") {
			inPull = true
			continue
		}
		if strings.Contains(l, "END_PULL") {
			inPull = false
			continue
		}
		if strings.Contains(l, "BEGIN_TAG") {
			inTag = true
			continue
		}
		if strings.Contains(l, "END_TAG") {
			inTag = false
			continue
		}
		if inPull {
			pullOutput = append(pullOutput, l)
		}
		if inTag {
			tagOutput = append(tagOutput, l)
		}
		if strings.HasPrefix(l, "PULL_RC:") {
			if n, err := strconv.Atoi(strings.TrimPrefix(l, "PULL_RC:")); err == nil {
				pullRC = &n
			}
		}
		if strings.HasPrefix(l, "TAG_RC:") {
			if n, err := strconv.Atoi(strings.TrimPrefix(l, "TAG_RC:")); err == nil {
				tagRC = &n
			}
		}
		if strings.HasPrefix(l, "EXIT:") {
			if n, err := strconv.Atoi(strings.TrimPrefix(l, "EXIT:")); err == nil {
				exitRC = &n
			}
		}
		lc := strings.ToLower(l)
		if strings.Contains(lc, "unauthorized") || strings.Contains(lc, "authentication required") ||
			strings.Contains(lc, "denied") || strings.Contains(lc, "tls:") ||
			strings.Contains(lc, "no such host") || strings.Contains(lc, "dial tcp") ||
			strings.Contains(lc, "connection refused") || strings.Contains(lc, "permission denied") ||
			strings.Contains(lc, "refused") {
			interesting = append(interesting, l)
		}
	}

	fmt.Println("---- 自动分析结果 ----")
	if exitRC != nil && *exitRC == 0 {
		fmt.Println("总体结果：成功（EXIT:0）—— source image 已 pull 到节点并 tag 为 target。")
		fmt.Printf("source: %s\n", source)
		fmt.Printf("target: %s\n", target)
		fmt.Println("建议：无需额外操作。")
		return
	}

	if pullRC != nil {
		fmt.Printf("Pull 返回码: %d\n", *pullRC)
	} else {
		fmt.Println("Pull 返回码: 未检测到（请查看完整日志）")
	}
	if tagRC != nil {
		fmt.Printf("Tag 返回码: %d\n", *tagRC)
	} else {
		fmt.Println("Tag 返回码: 未检测到（请查看完整日志）")
	}
	if exitRC != nil {
		fmt.Printf("最终 EXIT 码: %d\n", *exitRC)
	} else {
		fmt.Println("最终 EXIT 码: 未检测到（请查看完整日志）")
	}

	fmt.Println("\n可能的原因与建议：")
	if pullRC != nil && *pullRC != 0 {
		if usedSecret {
			if containsAny(interesting, []string{"unauthorized", "authentication required", "denied"}) {
				fmt.Println("- 认证失败：提供的凭证可能不正确或与 registry 不匹配。建议：检查 secret 内容（类型应为 kubernetes.io/dockerconfigjson），确认正确的 registry entry，或手动在节点上尝试用 docker/ctr 登录验证。")
			} else if containsAny(interesting, []string{"tls:", "certificate"}) {
				fmt.Println("- TLS/证书问题：registry TLS 证书可能不被信任或需要额外 CA。建议：在节点上确认 TLS 配置或使用可信 CA。")
			} else if containsAny(interesting, []string{"no such host", "dial tcp", "connection refused"}) {
				fmt.Println("- 网络/解析问题：节点无法访问 registry（DNS / 网络 / 防火墙）。建议：检查节点网络、DNS，或从节点上尝试 curl/ctr pull 以复现。")
			} else {
				fmt.Println("- 拉取失败（可能是凭证、网络或镜像名问题）。建议：查看上方 pull 输出以获取更详细的错误信息。")
			}
		} else {
			if containsAny(interesting, []string{"unauthorized", "authentication required", "denied"}) {
				fmt.Println("- 认证被拒绝：registry 需要凭证。建议：重试并传入 --image-pull-secret，或在节点上配置凭证。")
			} else if containsAny(interesting, []string{"no such host", "dial tcp", "connection refused"}) {
				fmt.Println("- 网络/解析问题：节点无法访问 registry。建议：检查节点网络/DNS/防火墙。")
			} else {
				fmt.Println("- 拉取失败：检查 pull 输出，确认 image 名正确（包含 registry）并确认 registry 可达。")
			}
		}
	} else if tagRC != nil && *tagRC != 0 {
		fmt.Println("- 镜像 pull 成功但 tag 失败：可能是 containerd 权限/版本或 target name 不合法。")
		fmt.Println("  建议：在节点上检查 /usr/bin/ctr 版本，手动尝试 ctr images tag <source> <target> 以复现并查看错误。")
	} else {
		fmt.Println("- 未能确定失败点，请查看完整日志（上方已打印）。")
	}

	if len(pullOutput) > 0 {
		fmt.Println("\n-- Pull 输出（首 20 行） --")
		for i, l := range pullOutput {
			if i >= 20 {
				break
			}
			fmt.Println(l)
		}
	}
	if len(tagOutput) > 0 {
		fmt.Println("\n-- Tag 输出（首 20 行） --")
		for i, l := range tagOutput {
			if i >= 20 {
				break
			}
			fmt.Println(l)
		}
	}

	fmt.Println("\n通用排查提示：")
	fmt.Println("- 确认 image 名是否包含 registry（例如 registry.example.com/repo/image:tag），若使用 docker hub 简写需确认节点如何解析。")
	fmt.Println("- 若使用私有 registry 且存在凭证问题，确保 secret 内容正确且命名空间正确（secret 必须在插件执行时所用的 namespace 中）。")
	fmt.Println("- 若怀疑 network/dns，ssh 到节点并尝试 curl / dig / ctr pull 以复现。")
	fmt.Println("- 若节点没有 ctr 或 containerd socket 位于非常规路径，请调整 debug 镜像或脚本以适配。")
	fmt.Println("- 该工具会创建 privileged pod 并 mount 主机路径，请确保拥有相应权限与安全审计。")
}

func containsAny(lines []string, subs []string) bool {
	for _, l := range lines {
		lc := strings.ToLower(l)
		for _, s := range subs {
			if strings.Contains(lc, s) {
				return true
			}
		}
	}
	return false
}
