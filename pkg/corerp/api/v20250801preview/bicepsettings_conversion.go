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
	v1 "github.com/radius-project/radius/pkg/armrpc/api/v1"
	"github.com/radius-project/radius/pkg/corerp/datamodel"
	"github.com/radius-project/radius/pkg/to"
)

// ConvertTo converts from the versioned BicepSettings resource to the datamodel representation.
func (src *BicepSettingsResource) ConvertTo() (v1.DataModelInterface, error) {
	converted := &datamodel.BicepSettings_v20250801preview{
		BaseResource: v1.BaseResource{
			TrackedResource: v1.TrackedResource{
				ID:       to.String(src.ID),
				Name:     to.String(src.Name),
				Type:     to.String(src.Type),
				Location: to.String(src.Location),
				Tags:     to.StringMap(src.Tags),
			},
			InternalMetadata: v1.InternalMetadata{
				UpdatedAPIVersion:      Version,
				AsyncProvisioningState: toProvisioningStateDataModel(src.Properties.ProvisioningState),
			},
		},
	}

	if src.Properties != nil {
		converted.Properties = datamodel.BicepSettingsProperties_v20250801preview{
			Authentication: bicepAuthenticationToDatamodel(src.Properties.Authentication),
		}
	}

	return converted, nil
}

// ConvertFrom converts from the datamodel BicepSettings resource to the versioned representation.
func (dst *BicepSettingsResource) ConvertFrom(src v1.DataModelInterface) error {
	bs, ok := src.(*datamodel.BicepSettings_v20250801preview)
	if !ok {
		return v1.ErrInvalidModelConversion
	}

	dst.ID = to.Ptr(bs.ID)
	dst.Name = to.Ptr(bs.Name)
	dst.Type = to.Ptr(bs.Type)
	dst.SystemData = fromSystemDataModel(&bs.SystemData)
	dst.Location = to.Ptr(bs.Location)
	dst.Tags = *to.StringMapPtr(bs.Tags)
	dst.Properties = &BicepSettingsProperties{
		ProvisioningState: fromProvisioningStateDataModel(bs.InternalMetadata.AsyncProvisioningState),
		Authentication:    bicepAuthenticationFromDatamodel(bs.Properties.Authentication),
	}

	return nil
}

func bicepAuthenticationToDatamodel(src *BicepAuthenticationConfiguration) *datamodel.BicepAuthenticationConfiguration {
	if src == nil {
		return nil
	}

	dst := &datamodel.BicepAuthenticationConfiguration{
		Registries: map[string]*datamodel.BicepRegistryAuthentication{},
	}

	for host, auth := range src.Registries {
		if auth == nil {
			continue
		}
		dst.Registries[host] = &datamodel.BicepRegistryAuthentication{
			Basic:                 bicepBasicToDatamodel(auth.Basic),
			AzureWorkloadIdentity: bicepAzureWiToDatamodel(auth.AzureWorkloadIdentity),
			AwsIrsa:               bicepAwsIrsaToDatamodel(auth.AwsIrsa),
		}
	}

	return dst
}

func bicepAuthenticationFromDatamodel(src *datamodel.BicepAuthenticationConfiguration) *BicepAuthenticationConfiguration {
	if src == nil {
		return nil
	}

	dst := &BicepAuthenticationConfiguration{
		Registries: map[string]*BicepRegistryAuthentication{},
	}

	for host, auth := range src.Registries {
		if auth == nil {
			continue
		}
		dst.Registries[host] = &BicepRegistryAuthentication{
			Basic:                 bicepBasicFromDatamodel(auth.Basic),
			AzureWorkloadIdentity: bicepAzureWiFromDatamodel(auth.AzureWorkloadIdentity),
			AwsIrsa:               bicepAwsIrsaFromDatamodel(auth.AwsIrsa),
		}
	}

	return dst
}

func bicepBasicToDatamodel(src *BicepBasicAuthentication) *datamodel.BicepBasicAuthentication {
	if src == nil {
		return nil
	}

	return &datamodel.BicepBasicAuthentication{
		Username: to.String(src.Username),
		Secret:   to.String(src.Secret),
	}
}

func bicepBasicFromDatamodel(src *datamodel.BicepBasicAuthentication) *BicepBasicAuthentication {
	if src == nil {
		return nil
	}

	return &BicepBasicAuthentication{
		Username: to.Ptr(src.Username),
		Secret:   to.Ptr(src.Secret),
	}
}

func bicepAzureWiToDatamodel(src *BicepAzureWorkloadIdentityAuthentication) *datamodel.BicepAzureWorkloadIdentityAuthentication {
	if src == nil {
		return nil
	}

	return &datamodel.BicepAzureWorkloadIdentityAuthentication{
		ClientID: to.String(src.ClientID),
		TenantID: to.String(src.TenantID),
		Secret:   to.String(src.Secret),
	}
}

func bicepAzureWiFromDatamodel(src *datamodel.BicepAzureWorkloadIdentityAuthentication) *BicepAzureWorkloadIdentityAuthentication {
	if src == nil {
		return nil
	}

	return &BicepAzureWorkloadIdentityAuthentication{
		ClientID: to.Ptr(src.ClientID),
		TenantID: to.Ptr(src.TenantID),
		Secret:   to.Ptr(src.Secret),
	}
}

func bicepAwsIrsaToDatamodel(src *BicepAwsIrsaAuthentication) *datamodel.BicepAwsIrsaAuthentication {
	if src == nil {
		return nil
	}

	return &datamodel.BicepAwsIrsaAuthentication{
		RoleArn: to.String(src.RoleArn),
		Secret:  to.String(src.Secret),
	}
}

func bicepAwsIrsaFromDatamodel(src *datamodel.BicepAwsIrsaAuthentication) *BicepAwsIrsaAuthentication {
	if src == nil {
		return nil
	}

	return &BicepAwsIrsaAuthentication{
		RoleArn: to.Ptr(src.RoleArn),
		Secret:  to.Ptr(src.Secret),
	}
}
