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

// ConvertTo converts from the versioned TerraformSettings resource to the datamodel representation.
func (src *TerraformSettingsResource) ConvertTo() (v1.DataModelInterface, error) {
	converted := &datamodel.TerraformSettings_v20250801preview{
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
		converted.Properties = datamodel.TerraformSettingsProperties_v20250801preview{
			TerraformRC: terraformCliConfigurationToDatamodel(src.Properties.Terraformrc),
			Backend:     terraformBackendToDatamodel(src.Properties.Backend),
			Env:         to.StringMap(src.Properties.Env),
			Logging:     terraformLoggingToDatamodel(src.Properties.Logging),
		}
	}

	return converted, nil
}

// ConvertFrom converts from the datamodel TerraformSettings resource to the versioned representation.
func (dst *TerraformSettingsResource) ConvertFrom(src v1.DataModelInterface) error {
	ts, ok := src.(*datamodel.TerraformSettings_v20250801preview)
	if !ok {
		return v1.ErrInvalidModelConversion
	}

	dst.ID = to.Ptr(ts.ID)
	dst.Name = to.Ptr(ts.Name)
	dst.Type = to.Ptr(ts.Type)
	dst.SystemData = fromSystemDataModel(&ts.SystemData)
	dst.Location = to.Ptr(ts.Location)
	dst.Tags = *to.StringMapPtr(ts.Tags)
	dst.Properties = &TerraformSettingsProperties{
		Terraformrc: terraformCliConfigurationFromDatamodel(ts.Properties.TerraformRC),
		Backend:     terraformBackendFromDatamodel(ts.Properties.Backend),
		Env:         stringMapToPointerMap(ts.Properties.Env),
		Logging:     terraformLoggingFromDatamodel(ts.Properties.Logging),
		ProvisioningState: fromProvisioningStateDataModel(
			ts.InternalMetadata.AsyncProvisioningState),
	}

	return nil
}

func terraformCliConfigurationToDatamodel(src *TerraformCliConfiguration) *datamodel.TerraformCliConfiguration {
	if src == nil {
		return nil
	}

	dst := &datamodel.TerraformCliConfiguration{}

	if src.Credentials != nil {
		dst.Credentials = make(map[string]*datamodel.TerraformCredentialConfiguration, len(src.Credentials))
		for host, cfg := range src.Credentials {
			if cfg == nil {
				continue
			}
			dst.Credentials[host] = &datamodel.TerraformCredentialConfiguration{
				Secret: to.String(cfg.Secret),
			}
		}
	}

	dst.ProviderInstallation = terraformProviderInstallationToDatamodel(src.ProviderInstallation)

	return dst
}

func terraformCliConfigurationFromDatamodel(src *datamodel.TerraformCliConfiguration) *TerraformCliConfiguration {
	if src == nil {
		return nil
	}

	dst := &TerraformCliConfiguration{}
	if src.Credentials != nil {
		dst.Credentials = make(map[string]*TerraformCredentialConfiguration, len(src.Credentials))
		for host, cfg := range src.Credentials {
			if cfg == nil {
				continue
			}
			dst.Credentials[host] = &TerraformCredentialConfiguration{
				Secret: to.Ptr(cfg.Secret),
			}
		}
	}

	dst.ProviderInstallation = terraformProviderInstallationFromDatamodel(src.ProviderInstallation)
	return dst
}

func terraformProviderInstallationToDatamodel(src *TerraformProviderInstallationConfiguration) *datamodel.TerraformProviderInstallationConfiguration {
	if src == nil {
		return nil
	}

	return &datamodel.TerraformProviderInstallationConfiguration{
		NetworkMirror: terraformNetworkMirrorToDatamodel(src.NetworkMirror),
		Direct:        terraformDirectToDatamodel(src.Direct),
	}
}

func terraformProviderInstallationFromDatamodel(src *datamodel.TerraformProviderInstallationConfiguration) *TerraformProviderInstallationConfiguration {
	if src == nil {
		return nil
	}

	return &TerraformProviderInstallationConfiguration{
		NetworkMirror: terraformNetworkMirrorFromDatamodel(src.NetworkMirror),
		Direct:        terraformDirectFromDatamodel(src.Direct),
	}
}

func terraformNetworkMirrorToDatamodel(src *TerraformNetworkMirrorConfiguration) *datamodel.TerraformNetworkMirrorConfiguration {
	if src == nil {
		return nil
	}

	return &datamodel.TerraformNetworkMirrorConfiguration{
		URL:     to.String(src.URL),
		Include: to.StringArray(src.Include),
		Exclude: to.StringArray(src.Exclude),
	}
}

func terraformNetworkMirrorFromDatamodel(src *datamodel.TerraformNetworkMirrorConfiguration) *TerraformNetworkMirrorConfiguration {
	if src == nil {
		return nil
	}

	dst := &TerraformNetworkMirrorConfiguration{
		URL: to.Ptr(src.URL),
	}

	dst.Include = stringSliceToPtrSlice(src.Include)
	dst.Exclude = stringSliceToPtrSlice(src.Exclude)

	return dst
}

func terraformDirectToDatamodel(src *TerraformDirectConfiguration) *datamodel.TerraformDirectConfiguration {
	if src == nil {
		return nil
	}

	return &datamodel.TerraformDirectConfiguration{
		Include: to.StringArray(src.Include),
		Exclude: to.StringArray(src.Exclude),
	}
}

func terraformDirectFromDatamodel(src *datamodel.TerraformDirectConfiguration) *TerraformDirectConfiguration {
	if src == nil {
		return nil
	}

	return &TerraformDirectConfiguration{
		Include: stringSliceToPtrSlice(src.Include),
		Exclude: stringSliceToPtrSlice(src.Exclude),
	}
}

func terraformBackendToDatamodel(src *TerraformBackendConfiguration) *datamodel.TerraformBackendConfiguration {
	if src == nil {
		return nil
	}

	dst := &datamodel.TerraformBackendConfiguration{
		Type:   to.String(src.Type),
		Config: map[string]any{},
	}

	for k, v := range src.Config {
		dst.Config[k] = v
	}

	return dst
}

func terraformBackendFromDatamodel(src *datamodel.TerraformBackendConfiguration) *TerraformBackendConfiguration {
	if src == nil {
		return nil
	}

	dst := &TerraformBackendConfiguration{
		Type:   to.Ptr(src.Type),
		Config: map[string]any{},
	}

	for k, v := range src.Config {
		dst.Config[k] = v
	}

	return dst
}

func terraformLoggingToDatamodel(src *TerraformLoggingConfiguration) *datamodel.TerraformLoggingConfiguration {
	if src == nil {
		return nil
	}

	dst := &datamodel.TerraformLoggingConfiguration{
		Path: to.String(src.Path),
	}

	if src.Level != nil {
		dst.Level = datamodel.TerraformLogLevel(*src.Level)
	}

	return dst
}

func terraformLoggingFromDatamodel(src *datamodel.TerraformLoggingConfiguration) *TerraformLoggingConfiguration {
	if src == nil {
		return nil
	}

	dst := &TerraformLoggingConfiguration{
		Path: to.Ptr(src.Path),
	}

	if src.Level != "" {
		level := TerraformLogLevel(src.Level)
		dst.Level = &level
	}

	return dst
}

func stringMapToPointerMap(src map[string]string) map[string]*string {
	if src == nil {
		return nil
	}

	dst := make(map[string]*string, len(src))
	for k, v := range src {
		val := v
		dst[k] = &val
	}
	return dst
}

func stringSliceToPtrSlice(values []string) []*string {
	if len(values) == 0 {
		return nil
	}

	result := make([]*string, len(values))
	for i, v := range values {
		valueCopy := v
		result[i] = &valueCopy
	}
	return result
}
