/*
Copyright 2024 The Radius Authors.

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

package v20250801preview

import (
	"testing"

	v1 "github.com/radius-project/radius/pkg/armrpc/api/v1"
	"github.com/radius-project/radius/pkg/corerp/datamodel"
	"github.com/radius-project/radius/pkg/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformSettingsConvertFromDatamodel(t *testing.T) {
	// arrange
	dm := &datamodel.TerraformSettings_v20250801preview{
		BaseResource: v1.BaseResource{
			TrackedResource: v1.TrackedResource{
				ID:       "/planes/radius/local/providers/Radius.Core/terraformSettings/corp",
				Name:     "corp",
				Type:     datamodel.TerraformSettingsResourceType_v20250801preview,
				Location: "radius-westus",
				Tags: map[string]string{
					"env": "prod",
				},
			},
			InternalMetadata: v1.InternalMetadata{
				AsyncProvisioningState: v1.ProvisioningStateSucceeded,
			},
		},
		Properties: datamodel.TerraformSettingsProperties_v20250801preview{
			TerraformRC: &datamodel.TerraformCliConfiguration{
				ProviderInstallation: &datamodel.TerraformProviderInstallationConfiguration{
					NetworkMirror: &datamodel.TerraformNetworkMirrorConfiguration{
						URL:     "https://mirror.corp.example.com/providers",
						Include: []string{"*"},
						Exclude: []string{"hashicorp/aws"},
					},
					Direct: &datamodel.TerraformDirectConfiguration{
						Exclude: []string{"hashicorp/aws"},
					},
				},
				Credentials: map[string]*datamodel.TerraformCredentialConfiguration{
					"app.terraform.io": {
						Secret: "/planes/radius/local/providers/Radius.Security/secrets/tfc-token",
					},
				},
			},
			Backend: &datamodel.TerraformBackendConfiguration{
				Type: "kubernetes",
				Config: map[string]any{
					"secret_suffix": "corp",
					"namespace":     "radius-system",
				},
			},
			Env: map[string]string{
				"TF_LOG": "TRACE",
			},
			Logging: &datamodel.TerraformLoggingConfiguration{
				Level: datamodel.TerraformLogLevel("TRACE"),
				Path:  "/var/log/terraform/terraform.log",
			},
		},
	}

	versioned := &TerraformSettingsResource{}

	// act
	err := versioned.ConvertFrom(dm)

	// assert
	require.NoError(t, err)
	assert.Equal(t, dm.ID, to.String(versioned.ID))
	assert.Equal(t, dm.Name, to.String(versioned.Name))
	assert.Equal(t, dm.Type, to.String(versioned.Type))
	assert.Equal(t, dm.Location, to.String(versioned.Location))
	require.NotNil(t, versioned.Properties)
	require.NotNil(t, versioned.Properties.Terraformrc)
	require.NotNil(t, versioned.Properties.Terraformrc.ProviderInstallation)
	assert.Equal(t, dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.URL, to.String(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.URL))
	assert.ElementsMatch(t, dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.Include, to.StringArray(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.Include))
	assert.ElementsMatch(t, dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.Exclude, to.StringArray(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.Exclude))
	require.NotNil(t, versioned.Properties.Terraformrc.Credentials["app.terraform.io"])
	assert.Equal(t, dm.Properties.TerraformRC.Credentials["app.terraform.io"].Secret, to.String(versioned.Properties.Terraformrc.Credentials["app.terraform.io"].Secret))
	require.NotNil(t, versioned.Properties.Backend)
	assert.Equal(t, dm.Properties.Backend.Type, to.String(versioned.Properties.Backend.Type))
	assert.Equal(t, dm.Properties.Backend.Config, versioned.Properties.Backend.Config)
	assert.Equal(t, dm.Properties.Env["TF_LOG"], to.String(versioned.Properties.Env["TF_LOG"]))
	require.NotNil(t, versioned.Properties.Logging)
	assert.Equal(t, string(dm.Properties.Logging.Level), string(*versioned.Properties.Logging.Level))
	assert.Equal(t, dm.Properties.Logging.Path, to.String(versioned.Properties.Logging.Path))
	assert.Equal(t, ProvisioningStateSucceeded, *versioned.Properties.ProvisioningState)
}

func TestTerraformSettingsConvertToDatamodel(t *testing.T) {
	// arrange
	versioned := &TerraformSettingsResource{
		ID:       to.Ptr("/planes/radius/local/providers/Radius.Core/terraformSettings/corp"),
		Name:     to.Ptr("corp"),
		Type:     to.Ptr("Radius.Core/terraformSettings"),
		Location: to.Ptr("radius-westus"),
		Tags: map[string]*string{
			"env": to.Ptr("prod"),
		},
		Properties: &TerraformSettingsProperties{
			Terraformrc: &TerraformCliConfiguration{
				ProviderInstallation: &TerraformProviderInstallationConfiguration{
					NetworkMirror: &TerraformNetworkMirrorConfiguration{
						URL:     to.Ptr("https://mirror.corp.example.com/providers"),
						Include: to.SliceOfPtrs("*"),
						Exclude: to.SliceOfPtrs("hashicorp/aws"),
					},
					Direct: &TerraformDirectConfiguration{
						Exclude: to.SliceOfPtrs("hashicorp/aws"),
					},
				},
				Credentials: map[string]*TerraformCredentialConfiguration{
					"app.terraform.io": {
						Secret: to.Ptr("/planes/radius/local/providers/Radius.Security/secrets/tfc-token"),
					},
				},
			},
			Backend: &TerraformBackendConfiguration{
				Type: to.Ptr("kubernetes"),
				Config: map[string]any{
					"secret_suffix": "corp",
				},
			},
			Env: map[string]*string{
				"TF_LOG": to.Ptr("TRACE"),
			},
			Logging: &TerraformLoggingConfiguration{
				Level: to.Ptr(TerraformLogLevelTrace),
				Path:  to.Ptr("/var/log/terraform/terraform.log"),
			},
			ProvisioningState: to.Ptr(ProvisioningStateSucceeded),
		},
	}

	// act
	dmInterface, err := versioned.ConvertTo()

	// assert
	require.NoError(t, err)
	dm := dmInterface.(*datamodel.TerraformSettings_v20250801preview)
	assert.Equal(t, to.String(versioned.ID), dm.ID)
	assert.Equal(t, to.String(versioned.Name), dm.Name)
	assert.Equal(t, to.String(versioned.Type), dm.Type)
	assert.Equal(t, to.String(versioned.Location), dm.Location)
	assert.Equal(t, to.StringMap(versioned.Tags), dm.Tags)
	require.NotNil(t, dm.Properties.TerraformRC)
	require.NotNil(t, dm.Properties.TerraformRC.ProviderInstallation)
	assert.Equal(t, to.String(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.URL), dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.URL)
	assert.Equal(t, to.StringArray(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.Include), dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.Include)
	assert.Equal(t, to.StringArray(versioned.Properties.Terraformrc.ProviderInstallation.NetworkMirror.Exclude), dm.Properties.TerraformRC.ProviderInstallation.NetworkMirror.Exclude)
	require.NotNil(t, dm.Properties.TerraformRC.Credentials["app.terraform.io"])
	assert.Equal(t, to.String(versioned.Properties.Terraformrc.Credentials["app.terraform.io"].Secret), dm.Properties.TerraformRC.Credentials["app.terraform.io"].Secret)
	require.NotNil(t, dm.Properties.Backend)
	assert.Equal(t, to.String(versioned.Properties.Backend.Type), dm.Properties.Backend.Type)
	assert.Equal(t, versioned.Properties.Backend.Config, dm.Properties.Backend.Config)
	assert.Equal(t, to.String(versioned.Properties.Env["TF_LOG"]), dm.Properties.Env["TF_LOG"])
	require.NotNil(t, dm.Properties.Logging)
	assert.Equal(t, datamodel.TerraformLogLevel(*versioned.Properties.Logging.Level), dm.Properties.Logging.Level)
	assert.Equal(t, to.String(versioned.Properties.Logging.Path), dm.Properties.Logging.Path)
	assert.Equal(t, v1.ProvisioningStateSucceeded, dm.InternalMetadata.AsyncProvisioningState)
}
