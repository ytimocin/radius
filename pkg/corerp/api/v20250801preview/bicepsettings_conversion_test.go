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

func TestBicepSettingsConvertFromDatamodel(t *testing.T) {
	dm := &datamodel.BicepSettings_v20250801preview{
		BaseResource: v1.BaseResource{
			TrackedResource: v1.TrackedResource{
				ID:       "/planes/radius/local/providers/Radius.Core/bicepSettings/registry-auth",
				Name:     "registry-auth",
				Type:     datamodel.BicepSettingsResourceType_v20250801preview,
				Location: "radius-westus",
				Tags: map[string]string{
					"env": "test",
				},
			},
			InternalMetadata: v1.InternalMetadata{
				AsyncProvisioningState: v1.ProvisioningStateSucceeded,
			},
		},
		Properties: datamodel.BicepSettingsProperties_v20250801preview{
			Authentication: &datamodel.BicepAuthenticationConfiguration{
				Registries: map[string]*datamodel.BicepRegistryAuthentication{
					"bicep.azurecr.io": {
						Basic: &datamodel.BicepBasicAuthentication{
							Username: "user",
							Secret:   "/planes/radius/local/providers/Radius.Security/secrets/basic-secret",
						},
					},
					"modules.aws.corp.example.com": {
						AwsIrsa: &datamodel.BicepAwsIrsaAuthentication{
							RoleArn: "arn:aws:iam::123456789012:role/RadiusBicepModules",
							Secret:  "/planes/radius/local/providers/Radius.Security/secrets/aws-secret",
						},
					},
					"internal.corp.example.com": {
						AzureWorkloadIdentity: &datamodel.BicepAzureWorkloadIdentityAuthentication{
							ClientID: "client-id",
							TenantID: "tenant-id",
							Secret:   "/planes/radius/local/providers/Radius.Security/secrets/wi-secret",
						},
					},
				},
			},
		},
	}

	versioned := &BicepSettingsResource{}
	require.NoError(t, versioned.ConvertFrom(dm))

	assert.Equal(t, dm.ID, to.String(versioned.ID))
	assert.Equal(t, dm.Name, to.String(versioned.Name))
	assert.Equal(t, dm.Type, to.String(versioned.Type))
	assert.Equal(t, dm.Location, to.String(versioned.Location))
	require.NotNil(t, versioned.Properties)
	require.NotNil(t, versioned.Properties.Authentication)
	require.NotNil(t, versioned.Properties.Authentication.Registries["bicep.azurecr.io"])
	require.NotNil(t, versioned.Properties.Authentication.Registries["bicep.azurecr.io"].Basic)
	assert.Equal(t, dm.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Username, to.String(versioned.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Username))
	assert.Equal(t, dm.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Secret, to.String(versioned.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Secret))
	require.NotNil(t, versioned.Properties.Authentication.Registries["modules.aws.corp.example.com"].AwsIrsa)
	assert.Equal(t, dm.Properties.Authentication.Registries["modules.aws.corp.example.com"].AwsIrsa.RoleArn, to.String(versioned.Properties.Authentication.Registries["modules.aws.corp.example.com"].AwsIrsa.RoleArn))
	require.NotNil(t, versioned.Properties.Authentication.Registries["internal.corp.example.com"].AzureWorkloadIdentity)
	assert.Equal(t, dm.Properties.Authentication.Registries["internal.corp.example.com"].AzureWorkloadIdentity.ClientID, to.String(versioned.Properties.Authentication.Registries["internal.corp.example.com"].AzureWorkloadIdentity.ClientID))
}

func TestBicepSettingsConvertToDatamodel(t *testing.T) {
	versioned := &BicepSettingsResource{
		ID:       to.Ptr("/planes/radius/local/providers/Radius.Core/bicepSettings/registry-auth"),
		Name:     to.Ptr("registry-auth"),
		Type:     to.Ptr("Radius.Core/bicepSettings"),
		Location: to.Ptr("radius-westus"),
		Tags: map[string]*string{
			"env": to.Ptr("test"),
		},
		Properties: &BicepSettingsProperties{
			Authentication: &BicepAuthenticationConfiguration{
				Registries: map[string]*BicepRegistryAuthentication{
					"bicep.azurecr.io": {
						Basic: &BicepBasicAuthentication{
							Username: to.Ptr("user"),
							Secret:   to.Ptr("/planes/radius/local/providers/Radius.Security/secrets/basic-secret"),
						},
					},
					"modules.aws.corp.example.com": {
						AwsIrsa: &BicepAwsIrsaAuthentication{
							RoleArn: to.Ptr("arn:aws:iam::123456789012:role/RadiusBicepModules"),
							Secret:  to.Ptr("/planes/radius/local/providers/Radius.Security/secrets/aws-secret"),
						},
					},
					"internal.corp.example.com": {
						AzureWorkloadIdentity: &BicepAzureWorkloadIdentityAuthentication{
							ClientID: to.Ptr("client-id"),
							TenantID: to.Ptr("tenant-id"),
							Secret:   to.Ptr("/planes/radius/local/providers/Radius.Security/secrets/wi-secret"),
						},
					},
				},
			},
			ProvisioningState: to.Ptr(ProvisioningStateSucceeded),
		},
	}

	dmInterface, err := versioned.ConvertTo()
	require.NoError(t, err)

	dm := dmInterface.(*datamodel.BicepSettings_v20250801preview)
	assert.Equal(t, to.String(versioned.ID), dm.ID)
	assert.Equal(t, to.String(versioned.Name), dm.Name)
	assert.Equal(t, to.String(versioned.Type), dm.Type)
	assert.Equal(t, to.String(versioned.Location), dm.Location)
	assert.Equal(t, to.StringMap(versioned.Tags), dm.Tags)
	require.NotNil(t, dm.Properties.Authentication)
	require.NotNil(t, dm.Properties.Authentication.Registries["bicep.azurecr.io"])
	assert.Equal(t, "user", dm.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Username)
	assert.Equal(t, "/planes/radius/local/providers/Radius.Security/secrets/basic-secret", dm.Properties.Authentication.Registries["bicep.azurecr.io"].Basic.Secret)
	require.NotNil(t, dm.Properties.Authentication.Registries["modules.aws.corp.example.com"].AwsIrsa)
	assert.Equal(t, "arn:aws:iam::123456789012:role/RadiusBicepModules", dm.Properties.Authentication.Registries["modules.aws.corp.example.com"].AwsIrsa.RoleArn)
	require.NotNil(t, dm.Properties.Authentication.Registries["internal.corp.example.com"].AzureWorkloadIdentity)
	assert.Equal(t, "client-id", dm.Properties.Authentication.Registries["internal.corp.example.com"].AzureWorkloadIdentity.ClientID)
	assert.Equal(t, v1.ProvisioningStateSucceeded, dm.InternalMetadata.AsyncProvisioningState)
}
