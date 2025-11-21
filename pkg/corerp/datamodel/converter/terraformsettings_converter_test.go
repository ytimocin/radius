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

package converter

import (
	"encoding/json"
	"testing"

	v1 "github.com/radius-project/radius/pkg/armrpc/api/v1"
	v20250801preview "github.com/radius-project/radius/pkg/corerp/api/v20250801preview"
	"github.com/radius-project/radius/pkg/corerp/datamodel"
	"github.com/stretchr/testify/require"
)

func TestTerraformSettingsModelRoundTrip(t *testing.T) {
	original := &datamodel.TerraformSettings_v20250801preview{
		BaseResource: v1.BaseResource{
			TrackedResource: v1.TrackedResource{
				ID:       "/planes/radius/local/providers/Radius.Core/terraformSettings/sample",
				Name:     "sample",
				Type:     datamodel.TerraformSettingsResourceType_v20250801preview,
				Location: "radius-westus",
			},
		},
		Properties: datamodel.TerraformSettingsProperties_v20250801preview{
			TerraformRC: &datamodel.TerraformCliConfiguration{
				ProviderInstallation: &datamodel.TerraformProviderInstallationConfiguration{
					NetworkMirror: &datamodel.TerraformNetworkMirrorConfiguration{
						URL: "https://mirror.example.com/providers",
					},
				},
				Credentials: map[string]*datamodel.TerraformCredentialConfiguration{
					"app.terraform.io": {Secret: "/planes/radius/local/providers/Radius.Security/secrets/token"},
				},
			},
			Backend: &datamodel.TerraformBackendConfiguration{Type: "kubernetes"},
			Env: map[string]string{
				"TF_LOG": "INFO",
			},
		},
	}

	versioned, err := TerraformSettingsModelToVersioned(original, v20250801preview.Version)
	require.NoError(t, err)

	raw, err := json.Marshal(versioned)
	require.NoError(t, err)

	converted, err := TerraformSettingsModelFromVersioned(raw, v20250801preview.Version)
	require.NoError(t, err)

	require.Equal(t, original.ID, converted.ID)
	require.Equal(t, original.Properties.TerraformRC.Credentials["app.terraform.io"].Secret, converted.Properties.TerraformRC.Credentials["app.terraform.io"].Secret)
	require.Equal(t, original.Properties.Env["TF_LOG"], converted.Properties.Env["TF_LOG"])
}
