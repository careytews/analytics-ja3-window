//
// Definition for ja3-window analytics
//

// Import KSonnet library.
local k = import "ksonnet.beta.2/k.libsonnet";

// Short-cuts to various objects in the KSonnet library.
local depl = k.extensions.v1beta1.deployment;
local container = depl.mixin.spec.template.spec.containersType;
local containerPort = container.portsType;
local resources = container.resourcesType;
local env = container.envType;
local annotations = depl.mixin.spec.template.metadata.annotations;
local hpa = k.autoscaling.v1.horizontalPodAutoscaler;
local svc = k.core.v1.service;
local svcPort = svc.mixin.spec.portsType;
local svcLabels = svc.mixin.metadata.labels;

// Import TNW helper library
local tnw = import "lib/tnw-common.libsonnet";

local ja3_window(config) = {

    local version = import "version.jsonnet",
    local pgm = "ja3-window",

    name: pgm,
    namespace: config.namespace,
    labels: {app:pgm, component:"analytics"},
    images: ["gcr.io/trust-networks/analytics-ja3-window:" + version],

    // Environment variables
    envs:: [
        env.new("AMQP_BROKER", "amqp")
    ],

    // Container definition.
    containers:: [
        container.new(self.name, self.images[0]) +
            container.env(self.envs) +
            container.command(["/usr/local/bin/ja3-window.py"]) +
            container.mixin.resources.limits({
                memory: "256M", cpu: "1.5"
            }) +
            container.mixin.resources.requests({
                memory: "256M", cpu: "0.5"
            })
    ],

    // Deployment definition
    deployments:: [
        depl.new(self.name, config.workers.replicas.ja3_window.min,
                 self.containers,
                 self.labels) +
                depl.mixin.metadata.namespace($.namespace) +
          annotations({"prometheus.io/scrape": "true",
            "prometheus.io/port": "8080"})
    ],

    autoScalers:: [
        tnw.horizontalPodAutoscaler(
            $.name,
            "analytics",
            config.workers.replicas.ja3_window.min,
            config.workers.replicas.ja3_window.max,
            80,
            ns=config.namespace
        )
    ],

    resources:
        if config.options.includeAnalytics then
	    self.deployments + self.autoScalers
	else [],
};

local resources(config) = {
    local ja3=ja3_window(config),
    images: ja3.images,

    resources:
        if config.options.includeAnalytics then
            ja3.resources
	else [],

};

[resources]
