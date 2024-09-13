/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"runtime/debug"
	"time"

	"github.com/sustainable-computing-io/kepler/pkg/bpf"
	"github.com/sustainable-computing-io/kepler/pkg/collector/stats"
	"github.com/sustainable-computing-io/kepler/pkg/config"
	"github.com/sustainable-computing-io/kepler/pkg/manager"
	"github.com/sustainable-computing-io/kepler/pkg/sensors/accelerator/gpu"
	"github.com/sustainable-computing-io/kepler/pkg/sensors/accelerator/qat"
	"github.com/sustainable-computing-io/kepler/pkg/sensors/components"
	"github.com/sustainable-computing-io/kepler/pkg/sensors/platform"
	kversion "github.com/sustainable-computing-io/kepler/pkg/version"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"k8s.io/klog/v2"
)

const (
	// to change these msg, you also need to update the e2e test
	finishingMsg    = "Exiting..."
	startedMsg      = "Started Kepler in %s"
	maxGPUInitRetry = 10
)

var (
	address                      = flag.String("address", "0.0.0.0:8888", "bind address")
	metricsPath                  = flag.String("metrics-path", "/metrics", "metrics path")
	enableGPU                    = flag.Bool("enable-gpu", false, "whether enable gpu (need to have libnvidia-ml installed)")
	enableQAT                    = flag.Bool("enable-qat", false, "whether enable qat (need to have Intel QAT driver installed)")
	enabledEBPFCgroupID          = flag.Bool("enable-cgroup-id", true, "whether enable eBPF to collect cgroup id (must have kernel version >= 4.18 and cGroup v2)")
	exposeHardwareCounterMetrics = flag.Bool("expose-hardware-counter-metrics", true, "whether expose hardware counter as prometheus metrics")
	enabledMSR                   = flag.Bool("enable-msr", false, "whether MSR is allowed to obtain energy data")
	kubeconfig                   = flag.String("kubeconfig", "", "absolute path to the kubeconfig file, if empty we use the in-cluster configuration")
	apiserverEnabled             = flag.Bool("apiserver", true, "if apiserver is disabled, we collect pod information from kubelet")
	redfishCredFilePath          = flag.String("redfish-cred-file-path", "", "path to the redfish credential file")
	exposeEstimatedIdlePower     = flag.Bool("expose-estimated-idle-power", false, "estimated idle power is meaningful only if Kepler is running on bare-metal or when there is only one virtual machine on the node")
)

func healthProbe(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`ok`))
	if err != nil {
		klog.Fatalf("%s", fmt.Sprintf("failed to write response: %v", err))
	}
}

func finalizing() {
	stack := "exit stack: \n" + string(debug.Stack())
	klog.Infof(stack)
	exitCode := 10
	klog.Infoln(finishingMsg)
	klog.FlushAndExit(klog.ExitFlushTimeout, exitCode)
}

func main() {
	start := time.Now()
	defer finalizing()
	klog.InitFlags(nil)
	flag.Parse()

	klog.Infof("Kepler running on version: %s", kversion.Version)

	config.SetEnabledEBPFCgroupID(*enabledEBPFCgroupID)                    // 设置 Cgroup ID, 内核版本大于 4.18。且为 cgroup v2 版则收集 Cgroup id
	config.SetEnabledHardwareCounterMetrics(*exposeHardwareCounterMetrics) // 设置 硬件计数指标
	config.SetEnabledGPU(*enableGPU)                                       // 设置 GPU
	config.SetEnabledQAT(*enableQAT)                                       // 设置 QAT
	config.EnabledMSR = *enabledMSR
	config.SetEnabledIdlePower(*exposeEstimatedIdlePower || components.IsSystemCollectionSupported()) // 设置 空闲功率是否开启

	config.SetKubeConfig(*kubeconfig)            // 设置 k8s kubeconfig 配置文件路径，默认为集群内的配置文件
	config.SetEnableAPIServer(*apiserverEnabled) // 是否从 APIServer 收集 pod 信息，禁用则从 kubelet 进行收集

	// set redfish credential file path          // 设置 redfish (经过搜索，这应该是一种行业政策。)
	if *redfishCredFilePath != "" {
		config.SetRedfishCredFilePath(*redfishCredFilePath)
	}

	config.LogConfigs() // 日志打印配置

	components.InitPowerImpl() // 初始化 电源管理模板（选择合适的管理模块，如果没有找到合适的，将采用估算方式）
	platform.InitPowerImpl()   // 设置电源管理模块，判断是否是 IBM 的 Z 系列架构，使用 PowerHMC 管理模块

	bpfExporter, err := bpf.NewExporter() // 创建一个 ebpf 导出器
	if err != nil {
		klog.Fatalf("failed to create eBPF exporter: %v", err)
	}
	defer bpfExporter.Detach()

	stats.InitAvailableParamAndMetrics(bpfExporter.GetEnabledBPFHWCounters(), bpfExporter.GetEnabledBPFSWCounters()) // 初始化可用参数和指标（参数1：硬件计数器，参数2：软件参数器）

	// 判断是否启用 GPU
	if config.EnabledGPU {
		klog.Infof("Initializing the GPU collector")
		// the GPU operators typically takes longer time to initialize than kepler resulting in error to start the gpu driver
		// therefore, we wait up to 1 min to allow the gpu operator initialize
		for i := 0; i <= maxGPUInitRetry; i++ {
			err = gpu.Init()
			if err == nil {
				break
			} else {
				time.Sleep(6 * time.Second)
			}
		}
		if err == nil {
			defer gpu.Shutdown()
		} else {
			klog.Infof("Failed to initialize the GPU collector: %v. Have the GPU operator initialize?", err)
		}
	}

	// 判断是否公开 QAT 指标
	if config.IsExposeQATMetricsEnabled() {
		klog.Infof("Initializing the QAT collector")
		if qatErr := qat.Init(); qatErr == nil {
			defer qat.Shutdown()
		} else {
			klog.Infof("Failed to initialize the QAT collector: %v", qatErr)
		}
	}

	m := manager.New(bpfExporter)                  // 初始化一个收集管理器
	reg := m.PrometheusCollector.RegisterMetrics() // 注册 普罗米修斯指标，包含进程、容器、虚拟机、节点
	defer components.StopPower()

	// starting a new gorotine to collect data and report metrics (启动新的 协程 来收集数据和报告指标)
	// BPF is attached here（ BPF 附加在此处 ）
	if startErr := m.Start(); startErr != nil {
		klog.Infof("%s", fmt.Sprintf("failed to start : %v", startErr))
	}
	metricPathConfig := config.GetMetricPath(*metricsPath) // 获取 指标路径，用于拼接 普罗米修斯
	bindAddressConfig := config.GetBindAddress(*address)   // 获取 绑定地址,用于监听

	http.Handle(metricPathConfig, promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			Registry: reg,
		},
	))
	http.HandleFunc("/healthz", healthProbe) // 健康探针
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, httpErr := w.Write([]byte(`<html>
                        <head><title>Energy Stats Exporter</title></head>
                        <body>
                        <h1>Energy Stats Exporter</h1>
                        <p><a href="` + metricPathConfig + `">Metrics</a></p>
                        </body>
                        </html>`))
		if err != nil {
			klog.Fatalf("%s", fmt.Sprintf("failed to write response: %v", httpErr))
		}
	})

	klog.Infof("starting to listen on %s", bindAddressConfig) // 开始监听
	ch := make(chan error)
	go func() {
		ch <- http.ListenAndServe(bindAddressConfig, nil)
	}()

	klog.Infof(startedMsg, time.Since(start)) // 日志输出启动时间
	klog.Flush()                              // force flush to parse the start msg in the e2e test
	err = <-ch
	klog.Fatalf("%s", fmt.Sprintf("failed to bind on %s: %v", bindAddressConfig, err)) // 收到通知退出
}
