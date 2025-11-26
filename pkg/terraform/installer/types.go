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

package installer

import "time"

// Operation enumerates installer operations.
type Operation string

const (
	// OperationInstall enqueues a Terraform install.
	OperationInstall Operation = "install"
	// OperationUninstall enqueues a Terraform uninstall.
	OperationUninstall Operation = "uninstall"
)

// VersionState enumerates installer states for a version.
type VersionState string

const (
	VersionStateInstalling   VersionState = "Installing"
	VersionStateSucceeded    VersionState = "Succeeded"
	VersionStateFailed       VersionState = "Failed"
	VersionStateUninstalling VersionState = "Uninstalling"
	VersionStateUninstalled  VersionState = "Uninstalled"
)

// HealthStatus enumerates health of an installed version.
type HealthStatus string

const (
	HealthUnknown   HealthStatus = "Unknown"
	HealthHealthy   HealthStatus = "Healthy"
	HealthUnhealthy HealthStatus = "Unhealthy"
)

// InstallRequest describes an install submission.
type InstallRequest struct {
	// Version requested for install (for example 1.6.4).
	Version string `json:"version"`
	// SourceURL is an optional direct archive URL to download Terraform from.
	SourceURL string `json:"sourceUrl"`
	// Checksum is an optional checksum string (for example sha256:<hash>).
	Checksum string `json:"checksum"`
}

// UninstallRequest describes an uninstall submission.
type UninstallRequest struct {
	// Version to uninstall.
	Version string `json:"version"`
}

// Status represents installer status metadata.
type Status struct {
	// Current is the active Terraform version.
	Current string `json:"current,omitempty"`
	// Previous is the prior Terraform version (used for rollback).
	Previous string `json:"previous,omitempty"`
	// Versions captures per-version metadata.
	Versions map[string]VersionStatus `json:"versions,omitempty"`
	// LastError captures the last error message from installer failures.
	LastError string `json:"lastError,omitempty"`
	// LastUpdated records the last time status was updated.
	LastUpdated time.Time `json:"lastUpdated,omitempty"`
}

// VersionStatus captures metadata for a specific Terraform version.
type VersionStatus struct {
	// Version is the Terraform version string.
	Version string `json:"version,omitempty"`
	// SourceURL used to download this version.
	SourceURL string `json:"sourceUrl,omitempty"`
	// Checksum used to validate the download.
	Checksum string `json:"checksum,omitempty"`
	// State represents the lifecycle state (for example Pending, Succeeded, Failed).
	State VersionState `json:"state,omitempty"`
	// Health captures health diagnostics for this version.
	Health HealthStatus `json:"health,omitempty"`
	// InstalledAt is the timestamp when the version was installed.
	InstalledAt time.Time `json:"installedAt,omitempty"`
	// LastError contains the last error for this version, if any.
	LastError string `json:"lastError,omitempty"`
}
