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

	v1 "github.com/radius-project/radius/pkg/armrpc/api/v1"
	v20250801preview "github.com/radius-project/radius/pkg/corerp/api/v20250801preview"
	"github.com/radius-project/radius/pkg/corerp/datamodel"
)

// TerraformSettingsModelToVersioned converts the datamodel TerraformSettings into the versioned API model.
func TerraformSettingsModelToVersioned(model *datamodel.TerraformSettings_v20250801preview, version string) (v1.VersionedModelInterface, error) {
	switch version {
	case v20250801preview.Version:
		versioned := &v20250801preview.TerraformSettingsResource{}
		if err := versioned.ConvertFrom(model); err != nil {
			return nil, err
		}
		return versioned, nil
	default:
		return nil, v1.ErrUnsupportedAPIVersion
	}
}

// TerraformSettingsModelFromVersioned converts the versioned TerraformSettings payload into the datamodel representation.
func TerraformSettingsModelFromVersioned(content []byte, version string) (*datamodel.TerraformSettings_v20250801preview, error) {
	switch version {
	case v20250801preview.Version:
		apiModel := &v20250801preview.TerraformSettingsResource{}
		if err := json.Unmarshal(content, apiModel); err != nil {
			return nil, err
		}
		dm, err := apiModel.ConvertTo()
		if err != nil {
			return nil, err
		}
		return dm.(*datamodel.TerraformSettings_v20250801preview), nil
	default:
		return nil, v1.ErrUnsupportedAPIVersion
	}
}
