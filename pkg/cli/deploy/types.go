/*
Copyright 2023 The Radius Authors.

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

package deploy

import (
	"context"

	"github.com/radius-project/radius/pkg/cli/clients"
	"github.com/radius-project/radius/pkg/cli/connections"
	"github.com/radius-project/radius/pkg/cli/workspaces"
)

// Interface is the interface for executing Bicep deployments in the CLI.
type Interface interface {
	// DeployWithProgress runs a deployment and displays progress to the user. This is intended to be used
	// from the CLI and thus logs to the console.
	DeployWithProgress(ctx context.Context, options Options) (clients.DeploymentResult, error)
}

// Options contains options to be used with DeployWithProgress.
type Options struct {
	// ConnectionFactory is used to create the deployment client.
	ConnectionFactory connections.Factory

	// Parameters should contain the parameters to set for the deployment.
	Parameters clients.DeploymentParameters

	// Template should contain a parsed ARM-JSON template.
	Template map[string]any

	// Workspace is the workspace to use for deployment.
	Workspace workspaces.Workspace

	// Providers are cloud and radius providers configured on the env for deployment
	Providers *clients.Providers

	// ProgressText is a message displayed on the console when deployment begins.
	ProgressText string

	// CompleteText is a message displayed on the console when deployment completes.
	CompletionText string
}

var _ Interface = (*Impl)(nil)

type Impl struct {
}

//go:generate mockgen -typed -destination=./mock_deploy.go -package=deploy -self_package github.com/radius-project/radius/pkg/cli/deploy github.com/radius-project/radius/pkg/cli/deploy Interface

// DeployWithProgress runs a deployment and displays progress to the user. This is intended to be used
// from the CLI and thus logs to the console.
func (*Impl) DeployWithProgress(ctx context.Context, options Options) (clients.DeploymentResult, error) {
	return DeployWithProgress(ctx, options)
}
